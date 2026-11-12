//! The accounts of a server, by id: those of its options first, then those
//! a resolver or a reload adds while the server runs. Ids are never reused,
//! and an account, once added, stays where it is: readers hold no lock.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustc_hash::FxHashMap;

use crate::imports::Imports;
use crate::imports::service::Responses;

/// The id of `$G`, the account of clients that name none.
pub(crate) const GLOBAL: u32 = 0;

/// Accounts in one chunk: ids share a chunk by all but their low 8 bits.
pub(crate) const CHUNK: usize = 256;

/// Accounts a server may have at most.
const MOST: usize = 1 << 20;

/// The id of account `id` within its chunk, and the chunk's place.
#[inline]
pub(crate) const fn place(id: u32) -> (usize, usize) {
    (id as usize / CHUNK, id as usize % CHUNK)
}

/// Chunks for `n` accounts.
pub(crate) const fn chunks(n: usize) -> usize {
    n.div_ceil(CHUNK)
}

/// One chunk of accounts: `CHUNK` of them.
type Chunk = Box<[OnceLock<Account>]>;

/// The accounts of a server.
#[derive(Debug)]
pub(crate) struct Accounts {
    /// By id, in chunks made on first use.
    chunks: Box<[OnceLock<Chunk>]>,
    /// Ids by name. Adding an account takes it.
    ids: RwLock<FxHashMap<Box<str>, u32>>,
    /// Accounts added so far.
    len: AtomicU32,
    /// A resolver adds accounts as clients and other servers name them.
    growing: bool,
}

/// One account and what the server keeps of it.
#[derive(Debug)]
pub(crate) struct Account {
    pub(crate) name: String,
    /// Its imports, once known: an account a resolver adds gets them
    /// when its JWT comes.
    imports: OnceLock<Imports>,
    /// The requests this server sent into it through service imports.
    pub(crate) responses: Arc<Responses>,
    /// The clients logged in to it, by id.
    pub(crate) conns: Mutex<BTreeSet<u64>>,
    /// The most clients it may have across the cluster: negative for no
    /// limit.
    limit: AtomicI64,
    /// Its loop detection subject on leaf node links.
    pub(crate) lds: String,
    /// When it was added or last updated, in nanoseconds since the epoch.
    updated: AtomicU64,
}

/// The imports of an account that has none.
static NO_IMPORTS: Imports = Imports {
    streams: Vec::new(),
    services: Vec::new(),
};

impl Account {
    /// Account `name`, with reply prefix `responses` for its requests.
    fn new(name: &str, responses: Responses) -> Account {
        Account {
            name: name.to_owned(),
            imports: OnceLock::new(),
            responses: Arc::new(responses),
            conns: Mutex::default(),
            limit: AtomicI64::new(-1),
            lds: crate::leaf::lds(),
            updated: AtomicU64::new(0),
        }
        .touched()
    }

    /// It, updated now.
    fn touched(self) -> Account {
        self.touch();
        self
    }

    /// Notes it updated now.
    pub(crate) fn touch(&self) {
        let since = SystemTime::now().duration_since(UNIX_EPOCH);
        // Nanoseconds fit until the year 2554.
        let nanos = since.map_or(0, |d| d.as_nanos() as u64);
        // Relaxed: monitoring reads it now and then; nothing else hangs
        // on it.
        self.updated.store(nanos, Ordering::Relaxed);
    }

    /// When it was added or last updated.
    pub(crate) fn updated(&self) -> SystemTime {
        // Relaxed: see `touch`.
        UNIX_EPOCH + Duration::from_nanos(self.updated.load(Ordering::Relaxed))
    }

    /// The most clients it may have across the cluster: negative for no
    /// limit.
    pub(crate) fn limit(&self) -> i64 {
        // Relaxed: a login that sees the old limit is as one before the
        // change.
        self.limit.load(Ordering::Relaxed)
    }

    /// Sets the most clients it may have, as its JWT or the options say.
    pub(crate) fn set_limit(&self, limit: i64) {
        // Relaxed: see `limit`.
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// Its imports: none until they are set.
    pub(crate) fn imports(&self) -> &Imports {
        self.imports.get().unwrap_or(&NO_IMPORTS)
    }

    /// Sets its imports, unless they were.
    pub(crate) fn set_imports(&self, imports: Imports) -> bool {
        self.imports.set(imports).is_ok()
    }
}

impl Accounts {
    /// Accounts `names`, by id, with `imports` each, and room for the most
    /// a server may have; more come from a resolver if `growing`. Each
    /// gets a reply prefix from `random`.
    pub(crate) fn new(
        names: &[String],
        imports: impl IntoIterator<Item = Imports>,
        growing: bool,
        mut random: impl FnMut() -> Responses,
    ) -> Accounts {
        let all = Accounts {
            chunks: (0..chunks(MOST)).map(|_| OnceLock::new()).collect(),
            ids: RwLock::default(),
            len: AtomicU32::new(0),
            growing,
        };
        let mut imports = imports.into_iter();
        for name in names {
            let id = all.add(name, &mut random);
            // None are set yet: an account of no imports may get them
            // once its JWT comes.
            if let (Some(id), Some(i)) = (id, imports.next())
                && !i.is_empty()
            {
                all.get(id).map(|a| a.set_imports(i));
            }
        }
        all
    }

    /// Accounts `names` and no more, with no imports: for tests.
    #[cfg(test)]
    pub(crate) fn of(names: &[&str]) -> Accounts {
        let names: Vec<String> = names.iter().map(|&n| n.to_owned()).collect();
        Accounts::new(&names, Vec::new(), false, || Responses::new(|n| n / 2))
    }

    /// Account `id`, if there is one.
    #[inline]
    pub(crate) fn get(&self, id: u32) -> Option<&Account> {
        let (chunk, at) = place(id);
        self.chunks.get(chunk)?.get()?.get(at)?.get()
    }

    /// The name of account `id`: `$G` if there is none.
    pub(crate) fn name(&self, id: u32) -> &str {
        self.get(id).map_or("$G", |a| a.name.as_str())
    }

    /// The imports of account `id`: none if there is no such account.
    pub(crate) fn imports(&self, id: u32) -> &Imports {
        self.get(id).map_or(&NO_IMPORTS, Account::imports)
    }

    /// The loop detection subject of account `id`, on leaf node links:
    /// empty if there is no such account.
    pub(crate) fn lds(&self, id: u32) -> &[u8] {
        self.get(id).map_or(&[][..], |a| a.lds.as_bytes())
    }

    /// The id of account `name`, if there is one.
    pub(crate) fn id(&self, name: &str) -> Option<u32> {
        self.ids.read().ok()?.get(name).copied()
    }

    /// The id of account `name`, if there is one: by its name in bytes.
    pub(crate) fn id_of(&self, name: &[u8]) -> Option<u32> {
        self.id(std::str::from_utf8(name).ok()?)
    }

    /// Whether accounts may be added past those of the options.
    pub(crate) const fn growing(&self) -> bool {
        self.growing
    }

    /// Chunks there is room for.
    pub(crate) fn room(&self) -> usize {
        self.chunks.len()
    }

    /// Accounts so far.
    pub(crate) fn len(&self) -> u32 {
        // Acquire: an account counted is in place, as `add` stores it.
        self.len.load(Ordering::Acquire)
    }

    /// Every account so far, with its id.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, &Account)> {
        (0..self.len()).filter_map(|id| Some((id, self.get(id)?)))
    }

    /// The id of account `name`, added if it is new, with a reply prefix
    /// from `random`: `None` once there is no room.
    pub(crate) fn add(&self, name: &str, random: impl FnOnce() -> Responses) -> Option<u32> {
        let mut ids = self.ids.write().ok()?;
        if let Some(&id) = ids.get(name) {
            return Some(id);
        }
        let id = self.len.load(Ordering::Relaxed);
        let (chunk, at) = place(id);
        let chunk = self.chunks.get(chunk)?.get_or_init(new_chunk);
        chunk.get(at)?.set(Account::new(name, random())).ok()?;
        ids.insert(name.into(), id);
        // Release: the account is in place before it is counted.
        self.len.store(id + 1, Ordering::Release);
        Some(id)
    }
}

/// A chunk with no accounts yet.
fn new_chunk() -> Chunk {
    (0..CHUNK).map(|_| OnceLock::new()).collect()
}

#[cfg(test)]
mod tests;
