//! Core NATS server.
//!
//! A [`Server`] runs on IO lanes: threads that each own their connections
//! and a full copy of the server's interest, so a message is routed without
//! locks. New connections go to the lanes in turn.
//!
//! Subjects with wildcards, queue groups, `UNSUB` maximums, accounts and
//! users work as in `nats-server`. So far over plain TCP.
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

mod auth;
mod config;
mod conn;
mod error;
mod index;
mod lane;
mod mailbox;
mod monitor;
mod options;
mod perms;
mod server;
mod stats;

pub use error::Error;
pub use options::{Login, Options, Permissions, Responses, Rules, User};
pub use server::Server;
