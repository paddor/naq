//! Core NATS server.
//!
//! A [`Server`] runs on IO lanes: threads that each own their connections
//! and a full copy of the server's interest, so a message is routed without
//! locks. New connections go to the lanes in turn.
//!
//! The server is a skeleton: one account, literal subjects, plain TCP, no
//! authentication. `SUB` with a wildcard or a queue group and `UNSUB` with
//! a maximum are refused with `-ERR`.
//!
//! # Examples
//!
//! ```
//! use std::io::{BufRead, BufReader, Write};
//! use std::net::TcpStream;
//!
//! let server = naq::Server::start(&naq::Options {
//!     host: "127.0.0.1".into(),
//!     port: 0,
//!     ..naq::Options::default()
//! })?;
//! let mut conn = TcpStream::connect(server.addr())?;
//! conn.write_all(b"CONNECT {\"verbose\":false}\r\nSUB greet 1\r\nPUB greet 2\r\nhi\r\nPING\r\n")?;
//! let mut lines = BufReader::new(conn).lines();
//! assert!(lines.next().unwrap()?.starts_with("INFO "));
//! assert_eq!(lines.next().unwrap()?, "MSG greet 1 2");
//! assert_eq!(lines.next().unwrap()?, "hi");
//! assert_eq!(lines.next().unwrap()?, "PONG");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod conn;
mod error;
mod index;
mod lane;
mod options;
mod server;

pub use error::Error;
pub use options::Options;
pub use server::Server;
