# naq

A Core NATS server in Rust, on the [zzq](https://github.com/paddor/zzq)
engine: shared-nothing IO lanes, no locks on the message path, batched
wakes and writes.

The server runs core publish and subscribe: wildcards, queue groups,
`UNSUB` maximums, accounts with stream and service imports between them,
users with passwords, tokens, NKeys or TLS certificates, auth callout,
operator mode with JWTs, permissions, over TCP, TLS and WebSocket. It
links to `nats-server` hubs as a leaf node, over TCP, TLS or WebSocket,
with credentials, failover across a hub cluster and the hub's
permissions. Servers of one cluster mesh over OMQ: they share their
clients' interest, carry messages one hop and tell clients of each other
for failover. naq leaf nodes link to naq hubs over OMQ too, by Go's leaf
rules, clusters on either side, with credentials, permissions and
failover across a hub cluster. It reads `nats-server` configuration
files (`naq -c FILE`), the keys it serves so far, and serves `/healthz`,
`/varz`, `/connz`, `/routez` and `/leafz` (`naq -m PORT`).

| Crate | Role |
| --- | --- |
| `naq-proto` | Sans-I/O `no_std` codec for the NATS client and leaf node protocols |
| `naq` | The server |
| `naq-bench` | Load generators and benchmarks (not published) |

## License

ISC or Apache-2.0, at your option.
