# Changelog

Notable changes to naq. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `naq`: a server skeleton on zzq IO lanes, and the `naq` binary (`-a`,
  `-p`, `--lanes`, `--name`). `INFO`, `CONNECT` (`verbose`, `echo`, `headers`),
  `PUB`, `HPUB`, `SUB`, `UNSUB`, `PING` and `PONG` on literal subjects;
  `MSG` and `HMSG` encoded into the subscriber's output and written in
  batches. Publishers wait for a subscriber past three quarters of
  `max_pending`; past it, the subscriber is closed. Wildcards, queue
  groups and `UNSUB` maximums are refused.
- `naq`: several lanes. Every lane holds the server's interest; a
  publish is forwarded once per lane with interest, in batches that slice
  the read buffer. The `PONG` after a `SUB` waits until every lane has it.
- `naq`: replies as `nats-server` orders and shapes them: `+OK` before a
  message's deliveries, none after a refused `SUB`; an `HPUB` from a client
  that did not ask for headers closes it. `INFO` carries `client_ip`, and
  a client of protocol 1 gets a second `INFO` naming its account after its
  first `PONG`.
- `naq`: wildcard subscriptions (`*`, `>`), queue groups and `UNSUB`
  maximums. Literal filters are looked up in a hash map, wildcard ones in
  a token trie. A queue group gets one pick per message on the
  publisher's lane, across the members on every lane; a member on another
  lane gets the message as a targeted forward. `pedantic` (on by default,
  as in `nats-server`) answers publishes to wildcard or broken subjects
  with `-ERR 'Invalid Publish Subject'`; `SUB` to a broken filter gets
  `-ERR 'Invalid Subject'`.
- `naq-proto`: `subject`, the rules of subjects and filters.
- `naq-proto`: the client wire codec. `client::parse` reads `CONNECT`,
  `PUB`, `HPUB`, `SUB`, `UNSUB`, `PING` and `PONG` as slices of the input,
  splitting arguments as `nats-server` does and enforcing
  `max_control_line` and `max_payload`. `encode` writes `MSG`, `HMSG`,
  `INFO`, `-ERR`, `+OK`, `PING` and `PONG`.
- `naq-bench`: `naq_codec`, the codec's cost on one core: parsing `PUB`,
  encoding `MSG`, and both.
- `naq-bench`: `naq_hop`, a batched OMQ hop between lanes of two contexts:
  publishes per second and round trip, with the sockets on the lanes or
  on OMQ's IO threads.
- `naq-bench`: `naq_index`, subject lookups in a hash map of literal
  subjects against zzq's topic trie.
- `naq-bench`: `naq_load`, a raw-wire NATS load generator. Batched
  publishers stamp each payload; subscribers count and check order. A
  shared window bounds messages in flight, so every message is delivered.
  Publish-only, fan-out and queue group runs; JSON records with server and
  load generator CPU.
- `naq-bench`: `naq_sink`, a fake server that measures the load generator
  alone: a sink for publishers, or a `MSG` source for subscribers.
