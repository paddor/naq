//! The load generator against the in-process sink and scripted servers.

#![expect(clippy::unwrap_used, reason = "tests fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::thread;
use std::time::{Duration, Instant};

use naq_bench::load::{self, Config, LoadError};
use naq_bench::sink::{Mode, Sink};

fn quick(addr: SocketAddr) -> Config {
    Config {
        addr,
        warmup: Duration::from_millis(50),
        duration: Duration::from_millis(200),
        drain: Duration::from_secs(5),
        // A small window keeps latency low, so deliveries land inside the
        // short measured time even on a loaded machine.
        window: 256 << 10,
        batch: 16 << 10,
        ..Config::default()
    }
}

fn relay() -> Sink {
    Sink::spawn("127.0.0.1:0".parse().unwrap(), Mode::Relay).unwrap()
}

#[test]
fn one_to_one_delivers_everything_in_order() {
    let sink = relay();
    let r = load::run(&quick(sink.addr())).unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert!(r.published > 0);
    assert_eq!(r.delivered, r.published);
    assert!(r.sub_msgs_s > 0.0 && r.pub_msgs_s > 0.0, "{r:?}");
    assert_eq!(r.server_version.as_deref(), Some("0.0.0-sink"));
    assert!(r.load_cpu_pct.is_some() && r.server_cpu_pct.is_none());
}

#[test]
fn fan_out_delivers_to_every_subscriber() {
    let sink = relay();
    let r = load::run(&Config {
        subs: 3,
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, 3 * r.published);
}

#[test]
fn queue_group_delivers_each_message_once() {
    let sink = relay();
    let r = load::run(&Config {
        subs: 3,
        queue: Some("workers".into()),
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, r.published);
}

#[test]
fn fan_in_keeps_order_per_publisher() {
    let sink = relay();
    let r = load::run(&Config {
        pubs: 3,
        payload: 1024,
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, r.published);
}

#[test]
fn small_window_and_unstamped_payloads_still_deliver() {
    let sink = relay();
    let r = load::run(&Config {
        payload: 4,
        window: 4096,
        batch: 4096,
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!(r.delivered, r.published);
}

#[test]
fn publish_only_reaches_the_sink() {
    let sink = relay();
    let r = load::run(&Config {
        subs: 0,
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert_eq!((r.delivered, r.sub_msgs_s), (0, 0.0));
    let deadline = Instant::now() + Duration::from_secs(5);
    while sink.published() < r.published {
        assert!(
            Instant::now() < deadline,
            "sink saw {} of {}",
            sink.published(),
            r.published
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn subscribe_only_counts_a_source() {
    let sink = Sink::spawn("127.0.0.1:0".parse().unwrap(), Mode::Source(64)).unwrap();
    let r = load::run(&Config {
        pubs: 0,
        subs: 2,
        payload: 64,
        ..quick(sink.addr())
    })
    .unwrap();
    assert!(r.is_clean(), "{r:?}");
    assert!(r.delivered > 0 && r.sub_msgs_s > 0.0);
    assert_eq!(r.published, 0);
}

#[test]
fn rejects_configs_that_cannot_run() {
    let addr = "127.0.0.1:1".parse().unwrap();
    let bad = [
        Config {
            pubs: 0,
            subs: 0,
            ..quick(addr)
        },
        Config {
            subs: 0,
            queue: Some("q".into()),
            ..quick(addr)
        },
        Config {
            payload: usize::MAX,
            ..quick(addr)
        },
        Config {
            batch: 0,
            ..quick(addr)
        },
        Config {
            window: 10,
            batch: 20,
            ..quick(addr)
        },
        Config {
            subject: "a b".into(),
            ..quick(addr)
        },
    ];
    for cfg in bad {
        assert!(
            matches!(load::run(&cfg), Err(LoadError::Config(_))),
            "{cfg:?}"
        );
    }
}

#[test]
fn fails_when_the_server_is_not_there() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let e = load::run(&quick(addr)).unwrap_err();
    assert!(e.to_string().starts_with("subscriber 0:"), "{e}");
    let e = load::run(&Config {
        subs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert!(e.to_string().starts_with("publisher 0:"), "{e}");
}

/// A server that completes handshakes, then runs `after` on each client
/// once it has sent `lines` more lines.
fn scripted(lines: usize, after: fn(&mut TcpStream)) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            thread::spawn(move || {
                s.write_all(b"INFO {}\r\n").unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                // CONNECT and PING, then the client's own lines.
                for _ in 0..2 + lines {
                    line.clear();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line.starts_with("PING") {
                        s.write_all(b"PONG\r\n").unwrap();
                    }
                }
                after(&mut s);
                thread::sleep(Duration::from_secs(10));
            });
        }
    });
    addr
}

#[test]
fn fails_on_a_server_error_during_the_run() {
    let addr = scripted(2, |s| s.write_all(b"-ERR 'Slow Consumer'\r\n").unwrap());
    let e = load::run(&Config {
        pubs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert_eq!(e.to_string(), "subscriber 0: server error: 'Slow Consumer'");
    let addr = scripted(0, |s| {
        s.write_all(b"-ERR 'Maximum Payload Violation'\r\n")
            .unwrap();
    });
    let e = load::run(&Config {
        subs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert_eq!(
        e.to_string(),
        "publisher: server error: 'Maximum Payload Violation'"
    );
}

#[test]
fn fails_when_the_server_closes_or_sends_junk() {
    let addr = scripted(2, |s| s.shutdown(std::net::Shutdown::Both).unwrap());
    let e = load::run(&Config {
        pubs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert_eq!(e.to_string(), "subscriber 0: connection closed by peer");
    let addr = scripted(0, |s| s.write_all(b"MSG a 1 0\r\n\r\n").unwrap());
    let e = load::run(&Config {
        subs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert_eq!(e.to_string(), "publisher: unexpected Msg");
    let addr = scripted(2, |s| s.write_all(b"SUB a 1\r\n").unwrap());
    let e = load::run(&Config {
        pubs: 0,
        ..quick(addr)
    })
    .unwrap_err();
    assert_eq!(e.to_string(), "subscriber 0: unexpected Sub");
}

static PONGS: AtomicUsize = AtomicUsize::new(0);

/// Pings the client, counts its PONGs and reads until it goes away.
fn ping_and_count(s: &mut TcpStream) {
    s.write_all(b"PING\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == b"PONG\r\n" {
            PONGS.fetch_add(1, SeqCst);
        }
    }
}

fn wait_for_pongs(n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while PONGS.load(SeqCst) < n {
        assert!(Instant::now() < deadline, "{} PONGs", PONGS.load(SeqCst));
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn answers_server_pings_during_the_run() {
    // A subscriber answers inline, a publisher in its next batch.
    let addr = scripted(2, ping_and_count);
    load::run(&Config {
        pubs: 0,
        ..quick(addr)
    })
    .unwrap();
    wait_for_pongs(1);
    let addr = scripted(0, ping_and_count);
    let r = load::run(&Config {
        subs: 0,
        ..quick(addr)
    })
    .unwrap();
    assert!(r.published > 0);
    wait_for_pongs(2);
}
