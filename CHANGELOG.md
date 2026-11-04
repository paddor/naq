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
- `naq`: NKey users (`Login::Nkey`, `{nkey: U...}` in a `users` list).
  With any, `INFO` carries a fresh nonce; the client signs it with the
  key's seed and sends `nkey` and `sig` in its `CONNECT`.
- `naq`: permissions (`Permissions`, `Rules`, `Responses`; `permissions`
  of a user, `default_permissions` of `authorization`). Publish and
  subscribe allow and deny lists of filters, `subject queue` entries for
  queue groups, and `allow_responses`, replies to requests a client got.
  Violations get `-ERR 'Permissions Violation for ...'` as `nats-server`
  words them; the connection stays. A wildcard subscription does not get
  messages on subjects its client may not subscribe to.
- `naq`: monitoring over HTTP: `/healthz`, `/varz` and `/connz` in the
  JSON of `nats-server`, with message and byte counts, connections, slow
  consumers and stale connections. `Options::http_port` and `http_host`,
  the `http_port`, `monitor_port` and `http` keys, and `-m PORT`;
  `Server::monitor_addr` tells where. Lanes count without atomics and
  publish their counts once per batch.
- `naq`: TLS for clients (`Options::tls`, `Tls`, the `tls` block with
  `cert_file`, `key_file`, `ca_file`, `verify`, `timeout` and
  `handshake_first`). As in `nats-server`, `INFO` goes out in the clear
  and the client starts the handshake; with `handshake_first` the
  handshake comes first. `verify` asks clients for certificates from the
  CA. `INFO` has `tls_required` and `tls_verify`.
- `naq`: the binary takes `-p -1` for a free port, `-l FILE` for its
  log, `-P FILE` for its process ID and accepts `--store_dir`, so
  harnesses that start `nats-server` can start naq. The `async-nats`
  client tests pass but those for lame duck mode and JWTs.
- `naq`: `Tls::fallback` and `handshake_first: "300ms"`: TLS first for
  clients that start it in time, `INFO` first for those that do not. A
  host name such as `localhost` binds its first IPv4 address, as Go
  binds it. The `async-nats` TLS, NKey, service and subject tests pass.
- `naq-proto`: the client wire codec. `client::parse` reads `CONNECT`,
  `PUB`, `HPUB`, `SUB`, `UNSUB`, `PING` and `PONG` as slices of the input,
  splitting arguments as `nats-server` does and enforcing
  `max_control_line` and `max_payload`. `encode` writes `MSG`, `HMSG`,
  `INFO`, `-ERR`, `+OK`, `PING` and `PONG`.
- `naq`: WebSocket clients (`Options::websocket`, `Websocket`, `Cookies`,
  the `websocket` block) on a port of their own, as `ws://` or, with
  `tls`, `wss://`; `Server::websocket_addr` tells where. The upgrade is
  checked and refused as `nats-server` does it, with `same_origin` and
  `allowed_origins`, `Nats-No-Masking`, `headers` added to the response and
  `handshake_timeout`. Frames carry the client protocol either way; text
  and fragmented frames are read, pings answered and close frames echoed.
  `compression` deflates messages over 64 bytes for clients that ask.
  `user_cookie`, `pass_cookie` and `token_cookie` fill a `CONNECT` without
  credentials, and `ping_interval` sets the WebSocket clients' own. A
  connection the server ends gets a close frame with the status of
  `nats-server`, and one that breaks the protocol gets status 1002 and its
  reason. The `async-nats` WebSocket tests pass.
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
- `naq-bench`: `naq_suite`, the benchmark suite. `naq_load` runs the same
  workloads against `nats-server` and naq, a fresh pinned server per run,
  the order alternating between repetitions, after an idle check. A table
  of medians and ratios follows. The perf gate (`--gate`) fails when
  naq's rate over `nats-server`'s on one publisher to one subscriber falls
  below a floor, or when the runs spread too wide to tell.
- `naq`: WebSocket clients' own credentials (`Websocket::auth`,
  `WebsocketAuth`; `authorization` and `no_auth_user` in the `websocket`
  block), as in `nats-server`: a user or token of their own stands in for
  the server's users and token, a `no_auth_user` for the server's, and a
  timeout for its own. `advertise` is accepted; `jwt_cookie` is refused, as
  `nats-server` refuses it without trusted operators.
- `naq-proto`: `leaf`, the leaf node wire. `leaf::parse` reads `INFO`,
  `CONNECT`, `LS+`, `LS-`, `LMSG`, `HMSG`, `PING`, `PONG`, `+OK` and `-ERR`
  from either side of a link, as slices of the input, splitting arguments
  as `nats-server` does. `leaf::sub`, `leaf::unsub`, `leaf::connect` and
  `leaf::Msg::encode` write what a leaf sends.
- `naq`: leaf node links to hubs (`Options::remotes`, `Remote`,
  `Options::leaf_reconnect`; `leafnodes { remotes, reconnect }`). Each
  remote dials its hub's URLs in turn, shuffled unless `no_randomize`:
  `nats-leaf://`, `nats://` or `host:port`, with credentials in the URL. It
  sends the `CONNECT` of a `nats-server` leaf, without compression, answers
  and sends `PING`s, and dials again after the interval, or 30 s after a
  loop or cluster name error and 5 s after a version refusal. The link
  carries no interest or messages yet.

### Changed

- `naq-proto`: `client::parse` reads the usual `PUB`, one space before
  each argument, in one pass, at half the cost; anything else goes the
  general way, with the same result.
- `naq`: a lane fills its clients' read buffers again once no batch for
  another lane refers to them, instead of allocating new ones; a batch
  for another lane starts at the size of the last.

### Fixed

- `naq`: the writer flushes after each write, so output a TLS stream
  buffered no longer waits for the client's next output.
- `naq`: the IPv4 wildcard host `0.0.0.0` binds as `[::]`, so IPv6
  clients get in too, as with `nats-server`.
- `naq`: a WebSocket client's `INFO` asks for credentials where a
  `no_auth_user` lets it in without, as `nats-server` asks.
- `naq`: `default_permissions` go to the users of lists alone, not to the
  single user of `authorization { user, password }` or to token clients,
  as in `nats-server`. The single user is `Options::user`, apart from
  `Options::users`; it cannot go with users lists or a token, and it is no
  `no_auth_user`.
