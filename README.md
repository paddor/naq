# naq

A Core NATS server in Rust, on the [zzq](https://github.com/paddor/zzq)
engine: shared-nothing IO lanes, no locks on the message path, batched
wakes and writes.

The server is a skeleton: literal subjects, plain TCP, no
authentication.

| Crate | Role |
| --- | --- |
| `naq-proto` | Sans-I/O `no_std` codec for the NATS client and leaf node protocols |
| `naq` | The server |
| `naq-bench` | Load generators and benchmarks (not published) |

## License

ISC or Apache-2.0, at your option.
