# naq fuzz targets

AFL targets for the inputs naq reads from outside. The package is not in
the workspace, so AFL's instrumentation stays out of normal builds.

| Target | Input | Checks |
| --- | --- | --- |
| `client_wire` | What a client sends | no panic, operations take what they say, a publish encodes as a message of the length given, a tab after the verb parses as a space |
| `certs` | A client certificate, or a DN user name | no panic, a certificate names no empty user, a DN equals itself |
| `config` | A configuration file, without includes | no panic |
| `jwts` | A JWT, decoded as each kind of claims | no panic |
| `leaf_wire` | What a leaf or its hub sends on a link | no panic, operations take what they say, messages and interest encode back to the same |
| `peer_frames` | A peer control message or data batch | no panic, what decodes encodes back to the same bytes |
| `subjects` | A subject and filters, one per line | the index and matching by hand agree |
| `websocket` | A WebSocket upgrade request, then frames | no panic, the reader keeps no more than it read, compression round trips |

Install the runner with `cargo install cargo-afl`. Then:

```sh
cargo afl build --release
target/release/seeds
cargo afl fuzz -i seeds/client_wire -o out/client_wire target/release/client_wire
```

`seeds` writes each target's seeds into `seeds/`. `cargo afl test
--release` replays the seeds, their truncations and one-byte flips, and
the inputs in `REGRESSIONS` in `tests/targets.rs`. Add a minimized crash
there before fixing it. `seeds/` and `out/` are not checked in.
