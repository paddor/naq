//! The peer wire: what naq servers send each other over OMQ, one message
//! per OMQ message: the servers of one cluster, and naq leafs and their
//! naq hubs.
//!
//! Control messages carry interest. A [`Hello`] comes first on every
//! connection, then a snapshot of the sender's interest and deltas to it,
//! numbered so that a receiver notices a loss, and beats that tell how far
//! the numbering got. Data messages are [`Batch`]es: publishes of one
//! account. Integers are little-endian; each string has its length first.
//! No allocation: encoders write into the caller's buffer, decoders return
//! slices of the input.
//!
//! # Examples
//!
//! ```
//! use naq_proto::peer::{self, Batch, Record};
//!
//! let mut out = Vec::new();
//! peer::batch(&mut out, None, b"$G");
//! Record {
//!     subject: b"orders",
//!     reply: None,
//!     headers: None,
//!     payload: b"hi",
//!     queue: Some(b"workers"),
//! }
//! .encode(&mut out);
//! let b = Batch::parse(&out)?;
//! assert_eq!(b.account, b"$G");
//! let r = b.records().next().unwrap()?;
//! assert_eq!((r.subject, r.queue), (&b"orders"[..], Some(&b"workers"[..])));
//! # Ok::<(), peer::Error>(())
//! ```

use bytes::BufMut;

/// The version of the peer wire this codec speaks, sent in [`Hello`].
pub const VERSION: u8 = 1;

const HELLO: u8 = 1;
const SNAPSHOT_START: u8 = 2;
const ENTRY: u8 = 3;
const SNAPSHOT_END: u8 = 4;
const DELTA: u8 = 5;
const BEAT: u8 = 6;
const RESYNC: u8 = 7;
const ERROR: u8 = 8;
const CONNECT: u8 = 9;
const BATCH: u8 = 16;

const REPLY: u8 = 1;
const HEADERS: u8 = 2;
const QUEUE: u8 = 4;

const INTEREST_QUEUE: u8 = 1;
const ORIGIN: u8 = 2;

/// Why a message does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// It ends before a field does.
    #[error("peer message cut short")]
    Short,
    /// Bytes are left after the last field.
    #[error("peer message runs on past its end")]
    Long,
    /// Its kind is none this codec knows.
    #[error("unknown peer message kind {0}")]
    Kind(u8),
    /// Flags or a tag this codec does not know.
    #[error("unknown peer message flags {0}")]
    Flags(u8),
    /// A [`Hello`] of another version of the wire.
    #[error("peer wire version {0}, not {VERSION}")]
    Version(u8),
}

/// A control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Control<'a> {
    /// Who the sender is; first on every connection.
    Hello(Hello<'a>),
    /// A snapshot of the sender's interest starts: as of delta `seq`.
    SnapshotStart {
        /// The sender's epoch.
        epoch: u64,
        /// The delta the snapshot includes; the next delta is `seq + 1`.
        seq: u64,
    },
    /// One entry of the snapshot.
    Entry(Interest<'a>),
    /// The snapshot is complete.
    SnapshotEnd {
        /// The sender's epoch.
        epoch: u64,
    },
    /// Interest changed.
    Delta {
        /// The sender's epoch.
        epoch: u64,
        /// One past the delta before it.
        seq: u64,
        /// The interest now; weight 0 for none.
        interest: Interest<'a>,
    },
    /// The sender is there, and sent deltas up to `seq`.
    Beat {
        /// The sender's epoch.
        epoch: u64,
        /// The last delta it sent.
        seq: u64,
    },
    /// The receiver lost track and asks for a snapshot.
    Resync,
    /// The link cannot go on, and the sender lets it go: why, as
    /// `nats-server` words its `-ERR`.
    Error(&'a [u8]),
    /// A leaf's credentials, after its hub's [`Hello`].
    Connect(Connect<'a>),
}

/// What the sender of a [`Hello`] is to the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Another server of its cluster.
    Route,
    /// A leaf node: it dialed the receiver as its hub.
    Leaf,
    /// The hub of the receiver, a leaf node.
    Hub,
}

/// Who a server is, and where its lanes take data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello<'a> {
    /// What the sender is to the receiver.
    pub role: Role,
    /// The account the link binds at the sender, between a leaf and its
    /// hub; empty on a route.
    pub account: &'a [u8],
    /// Random for each start of the server: a new one means it restarted.
    pub epoch: u64,
    /// Its server ID.
    pub server_id: &'a [u8],
    /// Its server name.
    pub name: &'a [u8],
    /// Its cluster name.
    pub cluster: &'a [u8],
    /// The data endpoint of each of its lanes, in lane order, separated by
    /// blanks.
    pub data: &'a [u8],
    /// The URLs its clients connect to, separated by blanks.
    pub client_urls: &'a [u8],
    /// The URLs naq leafs dial, separated by blanks: on a route, the
    /// sender's; from a hub, those of the servers of its cluster.
    pub leaf_urls: &'a [u8],
    /// From a hub, what its leaf signs with an NKey; else empty.
    pub nonce: &'a [u8],
}

/// What a leaf proves who it is with, as the `CONNECT` of a Go leaf does:
/// each field empty if not given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Connect<'a> {
    /// User name.
    pub user: &'a [u8],
    /// Its password.
    pub pass: &'a [u8],
    /// A token, in place of a user.
    pub token: &'a [u8],
    /// A public user NKey, in place of a user.
    pub nkey: &'a [u8],
    /// The hub's nonce, signed with the NKey's seed, in base64.
    pub sig: &'a [u8],
}

/// Interest of a server in `subject` of `account`: of plain subscriptions,
/// or of queue group `queue` with `weight` members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest<'a> {
    /// Account name.
    pub account: &'a [u8],
    /// Subject filter, not checked.
    pub subject: &'a [u8],
    /// Queue group name.
    pub queue: Option<&'a [u8]>,
    /// Members of the queue group; 1 for plain interest; 0 for none.
    pub weight: u32,
    /// On a route, the leaf node cluster the interest is of: the cluster
    /// of the leafs of the sender that have it, empty for leafs of none.
    /// `None` for the sender's clients.
    pub origin: Option<&'a [u8]>,
}

/// The words of `list`, a field of blank-separated words of [`Hello`].
pub fn words(list: &[u8]) -> impl Iterator<Item = &[u8]> {
    list.split(|&b| b == b' ').filter(|w| !w.is_empty())
}

impl Control<'_> {
    /// Appends the encoded message.
    pub fn encode(&self, out: &mut impl BufMut) {
        match self {
            Control::Hello(h) => h.encode(out),
            Control::SnapshotStart { epoch, seq } => {
                out.put_u8(SNAPSHOT_START);
                out.put_u64_le(*epoch);
                out.put_u64_le(*seq);
            }
            Control::Entry(i) => {
                out.put_u8(ENTRY);
                i.encode(out);
            }
            Control::SnapshotEnd { epoch } => {
                out.put_u8(SNAPSHOT_END);
                out.put_u64_le(*epoch);
            }
            Control::Delta {
                epoch,
                seq,
                interest,
            } => {
                out.put_u8(DELTA);
                out.put_u64_le(*epoch);
                out.put_u64_le(*seq);
                interest.encode(out);
            }
            Control::Beat { epoch, seq } => {
                out.put_u8(BEAT);
                out.put_u64_le(*epoch);
                out.put_u64_le(*seq);
            }
            Control::Resync => out.put_u8(RESYNC),
            Control::Error(why) => {
                out.put_u8(ERROR);
                short(out, why);
            }
            Control::Connect(c) => {
                out.put_u8(CONNECT);
                for s in [c.user, c.pass, c.token, c.nkey, c.sig] {
                    short(out, s);
                }
            }
        }
    }
}

impl Hello<'_> {
    fn encode(&self, out: &mut impl BufMut) {
        out.put_u8(HELLO);
        out.put_u8(VERSION);
        out.put_u8(match self.role {
            Role::Route => 0,
            Role::Leaf => 1,
            Role::Hub => 2,
        });
        out.put_u64_le(self.epoch);
        for s in [
            self.account,
            self.server_id,
            self.name,
            self.cluster,
            self.data,
            self.client_urls,
            self.leaf_urls,
            self.nonce,
        ] {
            short(out, s);
        }
    }
}

impl Interest<'_> {
    fn encode(&self, out: &mut impl BufMut) {
        out.put_u32_le(self.weight);
        short(out, self.account);
        short(out, self.subject);
        out.put_u8(
            (u8::from(self.queue.is_some()) * INTEREST_QUEUE)
                | (u8::from(self.origin.is_some()) * ORIGIN),
        );
        for s in [self.queue, self.origin].into_iter().flatten() {
            short(out, s);
        }
    }
}

/// Decodes the control message `msg`.
///
/// # Errors
///
/// A message cut short or too long, of an unknown kind, or a [`Hello`] of
/// another version.
pub fn decode(msg: &[u8]) -> Result<Control<'_>, Error> {
    let mut r = Reader(msg);
    let c = match r.u8()? {
        HELLO => {
            let version = r.u8()?;
            if version != VERSION {
                return Err(Error::Version(version));
            }
            let role = match r.u8()? {
                0 => Role::Route,
                1 => Role::Leaf,
                2 => Role::Hub,
                t => return Err(Error::Flags(t)),
            };
            Control::Hello(Hello {
                role,
                epoch: r.u64()?,
                account: r.short()?,
                server_id: r.short()?,
                name: r.short()?,
                cluster: r.short()?,
                data: r.short()?,
                client_urls: r.short()?,
                leaf_urls: r.short()?,
                nonce: r.short()?,
            })
        }
        SNAPSHOT_START => Control::SnapshotStart {
            epoch: r.u64()?,
            seq: r.u64()?,
        },
        ENTRY => Control::Entry(r.interest()?),
        SNAPSHOT_END => Control::SnapshotEnd { epoch: r.u64()? },
        DELTA => Control::Delta {
            epoch: r.u64()?,
            seq: r.u64()?,
            interest: r.interest()?,
        },
        BEAT => Control::Beat {
            epoch: r.u64()?,
            seq: r.u64()?,
        },
        RESYNC => Control::Resync,
        ERROR => Control::Error(r.short()?),
        CONNECT => Control::Connect(Connect {
            user: r.short()?,
            pass: r.short()?,
            token: r.short()?,
            nkey: r.short()?,
            sig: r.short()?,
        }),
        k => return Err(Error::Kind(k)),
    };
    r.done()?;
    Ok(c)
}

/// Publishes of one account, as a data message holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Batch<'a> {
    /// The leaf node cluster its publishes come from, if a leaf of the
    /// sender sent them: empty for a leaf of none.
    pub origin: Option<&'a [u8]>,
    /// Account name.
    pub account: &'a [u8],
    records: &'a [u8],
}

/// One publish in a [`Batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Subject, not checked.
    pub subject: &'a [u8],
    /// Reply subject.
    pub reply: Option<&'a [u8]>,
    /// The header block, from `NATS/1.0` to its empty line, not checked.
    pub headers: Option<&'a [u8]>,
    /// The payload.
    pub payload: &'a [u8],
    /// The queue group the sender picked a member of on the receiver; none
    /// for its plain subscriptions.
    pub queue: Option<&'a [u8]>,
}

/// Appends the head of a batch of `account`, from leaf cluster `origin`
/// if one; [`Record::encode`] appends its publishes.
pub fn batch(out: &mut impl BufMut, origin: Option<&[u8]>, account: &[u8]) {
    out.put_u8(BATCH);
    match origin {
        Some(o) => {
            out.put_u8(ORIGIN);
            short(out, o);
        }
        None => out.put_u8(0),
    }
    short(out, account);
}

impl Record<'_> {
    /// Appends the encoded publish, after a [`batch`] head.
    pub fn encode(&self, out: &mut impl BufMut) {
        let flags = (u8::from(self.reply.is_some()) * REPLY)
            | (u8::from(self.headers.is_some()) * HEADERS)
            | (u8::from(self.queue.is_some()) * QUEUE);
        out.put_u8(flags);
        short(out, self.subject);
        if let Some(r) = self.reply {
            short(out, r);
        }
        if let Some(q) = self.queue {
            short(out, q);
        }
        if let Some(h) = self.headers {
            long(out, h);
        }
        long(out, self.payload);
    }
}

impl<'a> Batch<'a> {
    /// Reads the head of the batch in `msg`.
    ///
    /// # Errors
    ///
    /// A message that is no batch, or one cut short.
    pub fn parse(msg: &'a [u8]) -> Result<Batch<'a>, Error> {
        let mut r = Reader(msg);
        match r.u8()? {
            BATCH => {}
            k => return Err(Error::Kind(k)),
        }
        let origin = match r.u8()? {
            0 => None,
            ORIGIN => Some(r.short()?),
            f => return Err(Error::Flags(f)),
        };
        let account = r.short()?;
        Ok(Batch {
            origin,
            account,
            records: r.0,
        })
    }

    /// Its publishes, in order. An error ends them.
    #[must_use]
    pub const fn records(&self) -> Records<'a> {
        Records(Reader(self.records))
    }
}

/// The publishes of a [`Batch`].
#[derive(Debug, Clone)]
pub struct Records<'a>(Reader<'a>);

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.0.is_empty() {
            return None;
        }
        let r = self.0.record();
        if r.is_err() {
            // Nothing after a broken record can be trusted.
            self.0 = Reader(&[]);
        }
        Some(r)
    }
}

/// Appends `s` with its length as a `u16`. Longer strings are cut: no
/// subject, name or URL of NATS is that long.
fn short(out: &mut impl BufMut, s: &[u8]) {
    let s = &s[..s.len().min(usize::from(u16::MAX))];
    // Fits: cut to u16::MAX above.
    out.put_u16_le(s.len() as u16);
    out.put_slice(s);
}

/// Appends `s` with its length as a `u32`.
fn long(out: &mut impl BufMut, s: &[u8]) {
    let s = &s[..s.len().min(u32::MAX as usize)];
    // Fits: cut to u32::MAX above.
    out.put_u32_le(s.len() as u32);
    out.put_slice(s);
}

/// The unread rest of a message.
#[derive(Debug, Clone)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    const fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Short);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn short(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn long(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()?;
        self.take(usize::try_from(n).map_err(|_| Error::Short)?)
    }

    fn interest(&mut self) -> Result<Interest<'a>, Error> {
        let weight = self.u32()?;
        let account = self.short()?;
        let subject = self.short()?;
        let flags = self.u8()?;
        if flags & !(INTEREST_QUEUE | ORIGIN) != 0 {
            return Err(Error::Flags(flags));
        }
        let queue = (flags & INTEREST_QUEUE != 0)
            .then(|| self.short())
            .transpose()?;
        let origin = (flags & ORIGIN != 0).then(|| self.short()).transpose()?;
        Ok(Interest {
            account,
            subject,
            queue,
            weight,
            origin,
        })
    }

    fn record(&mut self) -> Result<Record<'a>, Error> {
        let flags = self.u8()?;
        if flags & !(REPLY | HEADERS | QUEUE) != 0 {
            return Err(Error::Flags(flags));
        }
        let subject = self.short()?;
        let reply = (flags & REPLY != 0).then(|| self.short()).transpose()?;
        let queue = (flags & QUEUE != 0).then(|| self.short()).transpose()?;
        let headers = (flags & HEADERS != 0).then(|| self.long()).transpose()?;
        let payload = self.long()?;
        Ok(Record {
            subject,
            reply,
            headers,
            payload,
            queue,
        })
    }

    const fn done(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Long)
        }
    }
}
