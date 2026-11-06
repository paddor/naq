# naq

A Core NATS server in Rust, on the [zzq](https://github.com/paddor/zzq)
engine: shared-nothing IO lanes, no locks on the message path, batched
wakes and writes. NATS clients connect to it as to `nats-server`, and it
reads `nats-server` configuration files. Its tests run their scenarios
against `nats-server` v2.15.2 too, wherever both can, and expect the same
replies.

## What it does

- Core publish and subscribe: wildcards, queue groups, `UNSUB` maximums,
  headers, no responders. Clients over TCP, TLS (TLS first too) and
  WebSocket.
- Accounts with stream and service imports between them, and a system
  account.
- Users with passwords, tokens, NKeys or TLS certificates, permissions,
  connection types, and auth callout.
- Operator mode: JWTs of operators, accounts and users, with memory, full
  and cache resolvers. Account updates reach the clients already
  connected.
- A leaf node of `nats-server` hubs, over TCP, TLS or WebSocket, with
  credentials and failover across a hub cluster.
- Clusters of naq servers, meshed over OMQ, and naq leaf nodes of naq
  hubs.
- Monitoring: `/healthz`, `/varz`, `/connz`, `/routez` and `/leafz`.
- Logs as `nats-server` writes them, to stderr, a file (rotated by size)
  or a syslog, with debug lines and protocol traces on request.

A configuration key it does not serve is an error, not ignored.

## Not yet

- JetStream. A naq leaf reaches the JetStream of its `nats-server` hub.
- Routes to `nats-server`, gateways, and `nats-server` leaf nodes on a naq
  hub.
- Config reload, lame duck mode, signals, Prometheus metrics, and most
  `$SYS` requests and events.

## Usage

```sh
cargo install naq
naq -c nats.conf
naq -p 4222 -m 8222
```

Or embed a `Server`:

```rust
let options: naq::Options = "port: 4222\n".parse()?;
let server = naq::Server::start(&options)?;
```

| Crate | Role |
| --- | --- |
| `naq-proto` | Sans-I/O `no_std` codec for the NATS client and leaf node protocols |
| `naq` | The server, as a library and the `naq` binary |
| `naq-bench` | Load generators and benchmarks (not published) |

## License

ISC or Apache-2.0, at your option.
