# Changelog

Notable changes to naq. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `naq-bench`: `naq_load`, a raw-wire NATS load generator. Batched
  publishers stamp each payload; subscribers count and check order. A
  shared window bounds messages in flight, so every message is delivered.
  Publish-only, fan-out and queue group runs; JSON records with server and
  load generator CPU.
- `naq-bench`: `naq_sink`, a fake server that measures the load generator
  alone: a sink for publishers, or a `MSG` source for subscribers.
