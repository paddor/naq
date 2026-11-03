//! Sans-I/O codec for the NATS client protocol.
//!
//! [`client::parse`] reads what a client sends, as slices of the input.
//! [`encode`] writes what a server sends. No I/O and no allocation: the
//! caller owns every buffer.
//!
//! # Examples
//!
//! A publish turned into a delivery for subscription `1`:
//!
//! ```
//! use naq_proto::client::{self, ClientOp, Limits, Parsed};
//! use naq_proto::encode::Msg;
//!
//! let buf = b"PUB greet 5\r\nhello\r\n";
//! let Parsed::Op(ClientOp::Pub(p), _) = client::parse(buf, &Limits::default())? else {
//!     unreachable!()
//! };
//! let mut out = Vec::new();
//! Msg {
//!     subject: p.subject,
//!     sid: b"1",
//!     reply: p.reply,
//!     headers: p.headers,
//!     payload: p.payload,
//! }
//! .encode(&mut out);
//! assert_eq!(out, b"MSG greet 1 5\r\nhello\r\n");
//! # Ok::<(), client::ParseError>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod client;
pub mod encode;
mod num;
