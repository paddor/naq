//! Buffered frame reading over a TCP stream.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::wire::{self, Frame, MAX_CONTROL_LINE, MAX_PAYLOAD, Op, WireError};

/// Read buffer size. Large enough for many small frames per read.
const READ_BUF: usize = 1 << 20;

/// Time allowed for connecting and for each handshake reply.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// An I/O or protocol failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnError {
    /// Socket error.
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    /// Malformed frame from the peer.
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    /// The peer sent `-ERR`.
    #[error("server error: {0}")]
    Server(String),
    /// The peer closed the connection.
    #[error("connection closed by peer")]
    Closed,
    /// The peer sent something unexpected.
    #[error("unexpected {0}")]
    Unexpected(String),
}

/// Reads frames from a stream into one growing buffer.
#[derive(Debug)]
pub struct FrameReader {
    stream: TcpStream,
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl FrameReader {
    /// Wraps a stream.
    pub fn new(stream: TcpStream) -> FrameReader {
        FrameReader {
            stream,
            buf: vec![0; READ_BUF],
            start: 0,
            end: 0,
        }
    }

    /// The stream, for writing.
    pub const fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// The next complete frame in the buffer, without reading.
    ///
    /// # Errors
    ///
    /// A [`WireError`] if the buffered bytes are malformed.
    pub fn take_frame(&mut self) -> Result<Option<Frame<'_>>, WireError> {
        match wire::next_frame(&self.buf[self.start..self.end])? {
            Some((frame, used)) => {
                self.start += used;
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    /// Reads more bytes. Returns false at end of stream.
    ///
    /// # Errors
    ///
    /// The socket error.
    pub fn fill(&mut self) -> io::Result<bool> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            if self.start > 0 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            } else {
                // One frame fills the buffer; `next_frame` bounds its size.
                let max = MAX_PAYLOAD + MAX_CONTROL_LINE + 4;
                let len = (self.buf.len() * 2).min(max);
                if len == self.buf.len() {
                    return Err(io::Error::other("frame exceeds the read buffer"));
                }
                self.buf.resize(len, 0);
            }
        }
        let n = self.stream.read(&mut self.buf[self.end..])?;
        self.end += n;
        Ok(n > 0)
    }

    /// Reads until a frame is complete, answering `PING` and skipping
    /// `INFO` and `+OK`. Fails on `-ERR`.
    ///
    /// # Errors
    ///
    /// A [`ConnError`] on socket, protocol or server error.
    pub fn next_control(&mut self) -> Result<Frame<'_>, ConnError> {
        loop {
            // Peek without keeping the borrow, so the loop can read on.
            let step = match wire::next_frame(&self.buf[self.start..self.end])? {
                Some((f, _)) if f.op == Op::Err => {
                    return Err(ConnError::Server(lossy(f.args)));
                }
                Some((f, used)) => Some((f.op, used)),
                None => None,
            };
            match step {
                None => {
                    if !self.fill()? {
                        return Err(ConnError::Closed);
                    }
                }
                Some((Op::Info | Op::Ok, used)) => self.start += used,
                Some((Op::Ping, used)) => {
                    self.start += used;
                    self.stream.write_all(b"PONG\r\n")?;
                }
                Some((_, used)) => {
                    let at = self.start;
                    self.start += used;
                    let frame = wire::next_frame(&self.buf[at..at + used])?;
                    return frame
                        .map(|(f, _)| f)
                        .ok_or_else(|| ConnError::Unexpected("vanished frame".into()));
                }
            }
        }
    }
}

/// Lossy UTF-8 of a peer's bytes.
pub fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Server facts from the first `INFO`.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// `version`, if present.
    pub version: Option<String>,
}

/// Connects, reads `INFO`, sends `CONNECT` and `PING`, and waits for
/// `PONG`. Leaves the stream blocking without timeouts.
///
/// # Errors
///
/// A [`ConnError`] if the handshake fails.
pub fn handshake(addr: SocketAddr, name: &str) -> Result<(FrameReader, ServerInfo), ConnError> {
    let stream = TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut r = FrameReader::new(stream);
    let info = loop {
        if let Some(f) = r.take_frame()? {
            if f.op != Op::Info {
                return Err(ConnError::Unexpected(format!("{:?} before INFO", f.op)));
            }
            break parse_info(f.args);
        }
        if !r.fill()? {
            return Err(ConnError::Closed);
        }
    };
    let connect = format!(
        "CONNECT {{\"verbose\":false,\"pedantic\":false,\"name\":\"{name}\",\"lang\":\"rust\",\"version\":\"{}\",\"protocol\":1,\"echo\":false,\"headers\":false}}\r\nPING\r\n",
        env!("CARGO_PKG_VERSION")
    );
    r.stream().write_all(connect.as_bytes())?;
    expect_pong(&mut r)?;
    r.stream().set_read_timeout(None)?;
    Ok((r, info))
}

/// Waits for `PONG`.
///
/// # Errors
///
/// A [`ConnError`] if anything else arrives first.
pub fn expect_pong(r: &mut FrameReader) -> Result<(), ConnError> {
    let f = r.next_control()?;
    if f.op == Op::Pong {
        Ok(())
    } else {
        Err(ConnError::Unexpected(format!("{:?} instead of PONG", f.op)))
    }
}

fn parse_info(args: &[u8]) -> ServerInfo {
    let version = serde_json::from_slice::<serde_json::Value>(args)
        .ok()
        .and_then(|v| v.get("version")?.as_str().map(str::to_owned));
    ServerInfo { version }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn pair() -> (TcpStream, FrameReader) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        (server, FrameReader::new(client))
    }

    #[test]
    fn grows_the_buffer_for_a_frame_larger_than_it() {
        let (mut server, mut r) = pair();
        let size = READ_BUF + 100;
        thread::spawn(move || {
            let mut out = Vec::new();
            wire::write_msg(&mut out, b"big", b"1", &vec![b'x'; size]);
            server.write_all(&out).unwrap();
        });
        let f = r.next_control().unwrap();
        assert_eq!((f.op, f.payload.len()), (Op::Msg, size));
    }

    #[test]
    fn compacts_a_partial_frame_to_the_front() {
        let (mut server, mut r) = pair();
        // Fill the buffer exactly, ending inside a frame, so the next
        // fill has to move the partial frame to the front.
        let mut out = Vec::new();
        let filler = READ_BUF - 100;
        // "MSG a 1 " + 7 digits + CRLF, payload, CRLF.
        let payload = filler - 19;
        wire::write_msg(&mut out, b"a", b"1", &vec![b'x'; payload]);
        assert_eq!(out.len(), filler);
        wire::write_msg(&mut out, b"a", b"1", &[b'y'; 200]);
        thread::spawn(move || server.write_all(&out).unwrap());
        while r.end < READ_BUF {
            assert!(r.fill().unwrap());
        }
        assert_eq!(r.take_frame().unwrap().unwrap().payload.len(), payload);
        assert!(r.take_frame().unwrap().is_none());
        let f = r.next_control().unwrap();
        assert_eq!(f.payload, &[b'y'; 200]);
    }

    #[test]
    fn answers_ping_and_skips_info_and_ok() {
        let (mut server, mut r) = pair();
        server
            .write_all(b"INFO {}\r\n+OK\r\nPING\r\nPONG\r\n")
            .unwrap();
        expect_pong(&mut r).unwrap();
        let mut got = [0u8; 6];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"PONG\r\n");
    }

    #[test]
    fn reports_server_errors_and_close() {
        let (mut server, mut r) = pair();
        server
            .write_all(b"-ERR 'Authorization Violation'\r\n")
            .unwrap();
        let e = r.next_control().unwrap_err();
        assert_eq!(e.to_string(), "server error: 'Authorization Violation'");
        let (server, mut r) = pair();
        drop(server);
        assert!(matches!(r.next_control(), Err(ConnError::Closed)));
        let (mut server, mut r) = pair();
        server.write_all(b"MSG a 1 0\r\n\r\n").unwrap();
        assert!(matches!(expect_pong(&mut r), Err(ConnError::Unexpected(_))));
    }

    #[test]
    fn handshake_reads_info_and_waits_for_pong() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"INFO {\"version\":\"9.9.9\"}\r\n").unwrap();
            let mut r = io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            io::BufRead::read_line(&mut r, &mut line).unwrap();
            assert!(line.starts_with("CONNECT {"), "{line}");
            line.clear();
            io::BufRead::read_line(&mut r, &mut line).unwrap();
            assert_eq!(line, "PING\r\n");
            s.write_all(b"PONG\r\n").unwrap();
        });
        let (_r, info) = handshake(addr, "t").unwrap();
        assert_eq!(info.version.as_deref(), Some("9.9.9"));
        srv.join().unwrap();

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"PONG\r\n").unwrap();
        });
        assert!(matches!(
            handshake(addr, "t"),
            Err(ConnError::Unexpected(_))
        ));
    }
}
