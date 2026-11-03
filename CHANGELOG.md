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
- `naq`: request/reply status: a client with `no_responders` gets status
  503 on its reply subscription when no one got its request.
  `no_responders` without `headers`, and protocols other than 0 and 1,
  are refused with `-ERR` and closed.
- `naq-proto`: `encode::no_responders`.
- `naq`: `Options::lanes` and `--lanes` default to one lane per core the
  process may run on.
- `naq`: `Options::ping_interval`, `max_pings_out` and `write_deadline`,
  with the defaults of `nats-server`. The first `PING` comes 2 seconds
  after the `CONNECT`; later ones only to clients that were quiet for an
  interval. A client past its unanswered `PING`s gets
  `-ERR 'Stale Connection'` and is closed; one whose writes stall past the
  deadline is closed as a slow consumer.
- `naq`: `nats-server` configuration files. `Options::from_file` and
  `Options: FromStr` read the syntax (`:`, `=` or blanks between keys and
  values, maps, arrays, size suffixes, `$variables`, `include`) and the
  keys `listen`, `host`, `port`, `server_name`, `max_payload`,
  `max_control_line`, `max_pending`, `ping_interval`, `ping_max` and
  `write_deadline`; log settings are ignored, other keys are an error.
  The binary takes `-c FILE`; its other flags override the file.
- `naq`: `-ERR 'maximum control line exceeded'` in the case `nats-server`
  sends it.
- `naq`: accounts and authentication. `Options::accounts` and the
  `accounts` block add accounts beside `$G`, each with subjects of its
  own on every lane. `Options::users` (`User`, `Login::Password`), the
  `authorization` block (`user`, `password`, `users`, `token`,
  `timeout`) and the `users` of accounts say who may connect; passwords
  are plain or bcrypt hashes, compared off the lanes. `no_auth_user` lets
  clients without credentials in as that user. Without valid credentials
  a client gets `-ERR 'Authorization Violation'`; without a `CONNECT`
  within the timeout, `-ERR 'Authentication Timeout'`. `INFO` has
  `auth_required`, and the one after the first `PONG` the account's name.
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
