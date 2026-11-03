# Changelog

Notable changes to naq. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `naq`: a server skeleton on one zzq IO lane, and the `naq` binary
  (`-a`, `-p`, `--name`). `INFO`, `CONNECT` (`verbose`, `echo`, `headers`),
  `PUB`, `HPUB`, `SUB`, `UNSUB`, `PING` and `PONG` on literal subjects;
  `MSG` and `HMSG` encoded into the subscriber's output and written in
  batches. Publishers wait for a subscriber past three quarters of
  `max_pending`; past it, the subscriber is closed. Wildcards, queue
  groups, `UNSUB` maximums and more than one lane are refused.
- `naq-proto`: the client wire codec. `client::parse` reads `CONNECT`,
  `PUB`, `HPUB`, `SUB`, `UNSUB`, `PING` and `PONG` as slices of the input,
  splitting arguments as `nats-server` does and enforcing
  `max_control_line` and `max_payload`. `encode` writes `MSG`, `HMSG`,
  `INFO`, `-ERR`, `+OK`, `PING` and `PONG`.
- `naq-bench`: `naq_codec`, the codec's cost on one core: parsing `PUB`,
  encoding `MSG`, and both.
- `naq-bench`: `naq_load`, a raw-wire NATS load generator. Batched
  publishers stamp each payload; subscribers count and check order. A
  shared window bounds messages in flight, so every message is delivered.
  Publish-only, fan-out and queue group runs; JSON records with server and
  load generator CPU.
- `naq-bench`: `naq_sink`, a fake server that measures the load generator
  alone: a sink for publishers, or a `MSG` source for subscribers.
