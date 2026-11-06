# Changelog

Notable changes to naq. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `naq`: a log, as `nats-server` writes it: `[pid] time [LVL] text`, the
  start of the server in its order, clients created, refused and closed
  with Go's reasons and texts, permission violations, slow consumers,
  routes and leaf node links. `Options::log` (`Logging`, `LogTo`,
  `Trace`) and the keys `debug`, `trace`, `trace_verbose`,
  `trace_headers`, `logtime`, `logtime_utc`, `log_file`,
  `log_size_limit`, `log_max_num`, `syslog`, `remote_syslog` and
  `max_traced_msg_len`. Times are in UTC. The library logs nothing unless
  told; the binary logs to stderr. `Server::start` fails with `Error::Log`
  if the log file cannot be opened or the syslog not reached.
- `naq`: protocol traces of clients (`trace`): what each sent and got,
  payloads cut at `max_traced_msg_len`, secrets of a `CONNECT` left out.
- `naq`: log files rotated past `log_size_limit` and purged to
  `log_max_num`; `Server::reopen_log` opens the file again.
- `naq` binary: the log flags of `nats-server` (`-D`, `-V`, `-DV`, `-T`,
  `-l`, `-s`, `-r`, `--logtime_utc`, `--log_size_limit`,
  `--max_traced_msg_len`), with `-flag=value` and `--flag` forms, and `-n`
  for the server name.
- `naq`: `Options::config_file`, set by `Options::from_file`.
- `naq`: `Server::shutdown`, as `nats-server` shuts down: no new
  connections, then clients and hub links close with `Server Shutdown`
  once their lane delivered what was sent to it, and get a few seconds to
  write what is left.
- `naq`: `Signals::catch` and `Server::wait_for_signals`, caught before
  the server starts, as by `nats-server`: `INT`, `TERM` and `USR2` shut the
  server down, `USR1` opens the log file again, `HUP` is logged.
- `naq`: `Options::pid_file` (`pid_file`, `-P`) and
  `Options::ports_file_dir` (`ports_file_dir`, `--ports_file_dir`): the
  process ID, and the URLs the server listens at, in a file removed as it
  stops. `Error::Write` if they cannot be written.
- `naq` binary: `--signal` (`stop`, `quit`, `term`, `reopen`, `reload`,
  `ldm`, to a process ID, a pid file, or the one `naq` running), `-t`,
  `-v`, `--user`, `--pass`, `--auth`, the `--tls*` flags, `--cluster`,
  `--cluster_name` and `--routes`. Flags of `nats-server` naq does not
  serve say so.
- `naq`: monitoring served as `nats-server` serves it: HTTP/1.1 with
  keep-alive, any method, and Go's answers to requests it cannot read and
  to paths that are not clean; JSON in Go's layout and escaping; query
  options read as Go reads them, refused with its texts. `/varz` has all
  of Go's fields that apply, `/healthz` takes its options, and `/jsz`,
  `/gatewayz`, `/ipqueuesz`, `/raftz` and `/debug/vars` answer as Go does
  without JetStream, gateways or Raft.
- `naq`: `/connz` as `nats-server` serves it: every option, sort and
  page; activity, round trips, stalls, TLS and its client certificates,
  users, accounts and what issued a JWT user; links to hubs among the
  connections; and the connections that closed, with why, the newest
  `max_closed_clients` (`Options::max_closed_clients`) of them.
- `naq`: `/subsz` (`/subscriptionsz`) as `nats-server` serves it: counts
  by account, and the subscriptions of clients, paged and tested against
  a subject. `/routez` and `/leafz` in Go's fields: when a route came up
  and was last heard from, what it sent, round trips of links to Go hubs.
- `naq`: `/accountz` and `/accstatz` as `nats-server` serves them: the
  accounts, and one in detail with its exports, imports, connections and
  subscriptions; what the clients and links of each account sent and got,
  those that closed too. Subscription counts take in those `nats-server`
  makes for service imports and their replies. Accounts of JWTs show
  once in use, with their JWT, claims and revoked users; `/varz` shows
  the trusted operators and their claims.
- `naq`: `Options::https_port` (`https_port`, `https`, `-ms`): monitoring
  over HTTPS with the certificate of the client port, and
  `Options::http_base_path` (`http_base_path`).
- `naq`: server requests on `$SYS`, as `nats-server` answers them, from
  every server of a cluster: `$SYS.REQ.SERVER.PING`, and `PING.<Z>` or
  `<id>.<Z>` for `IDZ`, `STATSZ`, `VARZ`, `SUBSZ`, `CONNZ`, `ROUTEZ`,
  `GATEWAYZ`, `LEAFZ`, `ACCOUNTZ`, `HEALTHZ`, `JSZ`, `PROFILEZ`, `EXPVARZ`,
  `IPQUEUESZ` and `RAFTZ`. Their options, server filters and errors are
  Go's, and answers are compressed as `Accept-Encoding` asks.
- `naq`: account requests on `$SYS`, as `nats-server` answers them:
  `$SYS.REQ.ACCOUNT.<acc>.SUBSZ`, `CONNZ`, `LEAFZ`, `JSZ`, `INFO`, `STATZ`
  and `CONNS`, `$SYS.REQ.ACCOUNT.PING.STATZ`, and a user's own details on
  `$SYS.REQ.USER.INFO`, answered by its server only. The system account
  exports them, and every account imports those about itself, as in
  `nats-server`; `/accountz` shows them.
- `naq`: `Options::server_tags` (`server_tags`) and
  `Options::server_metadata` (`server_metadata`), shown in `/varz` and on
  `$SYS`.

### Changed

- `naq` binary: a configuration it cannot use exits 1, as `nats-server`;
  flags it cannot read exit 2.
- `naq`: a monitoring port of -1 picks a free one and 0 serves none, as
  in `nats-server` (`http_port`, `https_port`, `-m`, `-ms`); `listen`
  addresses take port -1.
- `naq`: in operator mode, the system account is the one named, by
  `system_account` or the operator JWT; without one there is none, as in
  `nats-server`.

### Fixed

- `naq`: a client that breaks the protocol is closed as `Protocol
  Violation`, as by `nats-server`, in the log and in the WebSocket close
  frame; a client without credentials is the `no_auth_user` in the user
  service imports tell of.
- `naq`: plain subscriptions get a message from another server of the
  cluster, or from a naq hub or leaf, once, not twice, where a queue group
  of theirs matches it too and gets its pick there.

## [0.1.0] - 2026-11-05

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
  loop or cluster name error and 5 s after a version refusal.
- `naq`: a leaf node link tells its hub of the interest of its account's
  clients: an `LS+` for each subject on the link, queue groups with their
  member counts, and its `$LDS.` loop detection subject, then `LS+` and
  `LS-` as interest comes and goes. Literal JetStream subjects, which
  `nats-server` refuses across links, are left out. Its own `$LDS.` coming
  back from the hub ends the link for 30 s.
- `naq`: messages reach hubs over leaf node links. The hub's `LS+` and
  `LS-` become interest on every lane, and a message reaches each link
  once, as `LMSG` or `HMSG`, with the queue groups picked for it after `|`
  or `+ reply`. A hub's queue group gets a message only when no client of
  the server takes it.
- `naq`: messages of hubs reach clients over leaf node links. An `LMSG`
  or `HMSG` goes to every plain subscription and to one member of each
  queue group it lists, on any lane, and to other links, but never back to
  the hub it came from. Messages on `$JS.API.>`, `$KV.>` and `$OBJ.>`, and
  hub interest in literal subjects among them, are dropped. A subscriber
  past the stall mark slows the link's reads.
- `naq`: credentials for leaf node links (`Remote::credentials`,
  `Remote::nkey`; `credentials`/`creds` and `nkey`/`seed` of a remote). A
  user NKey seed signs the hub's nonce and sends its public key; a
  credentials file, read at each dial, sends its user JWT and signs with
  its seed. Both on one remote, or a seed that is not a user's, is a
  config error. Two remotes differ by their credentials too.
- `naq`: TLS on leaf node links (`Remote::tls`, `RemoteTls`; `tls` of a
  remote). The link starts TLS after the hub's first `INFO` when the remote
  has `tls` or the hub asks for it, or before it with `handshake_first`.
  The hub's certificate must chain to `ca_file`, else to the system's
  authorities, and name the URL's host, or for an IP, the first host name
  of the remote's URLs. `cert_file` and `key_file` give a certificate for
  hubs that verify leafs. A file that cannot be read stops the start.
- `naq`: leaf node links over WebSocket: `ws://` and `wss://` remote URLs,
  with TLS first for `wss://` or a remote with `tls`. The link asks for
  the URL's path with `/leafnode` after it, checks the hub's answer as
  `nats-server` does, and masks its frames; it does not compress them. A
  remote cannot mix WebSocket and other URLs.
- `naq`: leaf node links fail over across a hub cluster. Each `INFO` with
  `leafnode_urls`, or `ws_connect_urls` for a WebSocket remote, sets the
  URLs to dial next, as `nats-server` sets them: those but ones configured,
  then the configured ones. They take the scheme of the configured URLs
  and the credentials of the first configured URL with some.
- `naq`: permissions on leaf node links (`Remote::deny_imports`,
  `Remote::deny_exports`, `Remote::request_isolation`; `deny_imports`,
  `deny_exports` and `request_isolation` of a remote). The hub's `import`
  and `export` in `connect_info`, with the remote's denies, decide what the
  link tells the hub of and takes from it, and what it sends and takes
  interest in: other messages are dropped, and literal hub interest is left
  out, as a `nats-server` leaf does, so the hub keeps the link. Service
  replies (`_R_.`) and JetStream acks always come in. The `CONNECT` sends
  `deny_imports` as `deny_pub`, and `isolate` when asked.
- `naq`: with several leaf node remotes, the `$LDS.` loop detection
  subjects of one hub are told to the others, never back to it, so loops
  through the server are found. Other interest of a hub stays with it, as
  in `nats-server`.
- `naq`: `/leafz` shows the server's leaf node links as `nats-server` does:
  the hub's name and address, the link's account, its message counts, and
  the subjects of the hub's interest with `subs=1`.
- `naq`: clients of a leaf node use the JetStream of its hub through the
  hub's domain (`$JS.<domain>.API`), pull consumers and acks included. A
  message of a hub whose `$JS.ACK.` reply ends in `@` and a subject reaches
  clients with that subject and the reply before the `@`, as `nats-server`
  hands it on; links get it as it came.
- `naq-proto`: `peer`, the wire of naq servers over OMQ: of one cluster,
  and of naq leafs and their naq hubs. Control messages (`peer::Control`:
  `Hello` with the sender's `peer::Role`, snapshot and numbered deltas of
  interest, beats, resync) and data batches (`peer::Batch` of
  `peer::Record`s, with the leaf cluster they come from), encoded into the caller's buffer and decoded as
  slices, with a fuzz target, `peer_frames`.
- `naq`: clusters of naq servers (`Options::cluster`, `Cluster`; `cluster {
  name, listen, routes }`). Lane 0 binds the cluster port, which
  `Server::cluster_addr` gives, dials every route over OMQ and greets the
  server there; each lane binds a data socket. `/routez` shows the routes
  to servers that answered. A server of another cluster name is not met;
  one that stops leaves the routes. A route that does not greet in 3 s is
  dialed again. A server that stops reading and sending is let go after
  3 s of silence, even while what it is told backs up.
- `naq`: the servers of a cluster tell each other of their clients'
  interest: a snapshot on each connection, then numbered deltas and beats;
  a server that sees a gap, or a snapshot cut short, asks for a snapshot
  again. Each server told has a sender and a queue of its own, so one that
  falls behind holds up no other; past 65536 waiting messages, a snapshot
  replaces them. Plain interest is
  told once, a queue group with its member count. A server gone takes its
  interest with it. `/routez` counts each route's subscriptions.
- `naq`: messages cross the cluster. A message goes once to each other
  server with plain interest, on the publishing lane's data link to it, as
  a batch per read; a queue group gets one pick at the source across
  members here and at other servers, each counted as its weight. The
  receiving server delivers to its clients and lanes, to no other server,
  and to its links only for a queue group without a member here. A
  message of a hub stays with the server linked to it, and a hub gets
  only the messages of the server linked to it, as in `nats-server`:
  every server links to the hub of its own. A server
  gone closes the data links to it: a publisher waiting on one goes on.
- `naq`: a client of a cluster server gets `connect_urls` in `INFO`: its
  server's client address, then those of the other servers that are up.
- `naq`: a server of a cluster names it in its leaf `CONNECT`, so a Go hub
  cluster keeps the interest and messages of one server of the cluster
  from the links of the others.
- `naq`: `/routez?subs=1` and `subs=detail` list each route's
  subscriptions, as `nats-server` does. A detail of a queue group adds its
  members at that server as `queue_weight`.
- `naq`: naq leaf nodes of naq hubs, over OMQ. A hub takes them on
  `leafnodes { listen }` (`Options::leafnodes`, `Leafnodes`;
  `Server::leafnode_addr`), each bound to `authorization { account }` or
  `$G`; a leaf dials a remote of one `naq://host:port` URL. Each side
  tells the other of its interest, as routes do, by Go's leaf rules: a
  leaf hears of all interest but its own and its cluster's, a hub of the
  leaf's clients and leafs, the routes of a hub of its leafs' interest by
  cluster. Messages go one way per link and never back to their leaf
  cluster; a queue group takes a member across a link only without one
  nearer. Only the leaf dials: its data goes over DEALERs to a ROUTER on
  every lane of the hub. Up to 64 routes, hubs and leafs. A leaf gone
  takes its interest; `/leafz` shows naq links.
- `naq`: a naq leaf remote takes several `naq://` URLs, tried in turn and
  shuffled unless `no_randomize`. A URL that refuses the connection, or
  whose hub says nothing for 3 s, gives way to the next. A hub tells its
  leafs where its cluster's servers take leafs, and those URLs come first
  after a link, as in `nats-server`; `peer::Hello` has `leaf_urls`.
- `naq`: naq links find loops as `nats-server` does. Each side tells the
  other of its account's `$LDS.` subject; a side that hears its own back
  sends `peer::Control::Error` (`Loop detected for leafnode account=...`)
  and lets the link go, and the leaf waits 30 s before it dials again.
- `naq`: naq leafs log in to their naq hub as Go leafs do. The hub
  answers a leaf's `Hello` with its own and a nonce; the leaf sends
  `peer::Control::Connect` with the user and password or token of its URL,
  or its `nkey` and the nonce signed. The hub takes the users of
  `leafnodes { authorization { user, password, nkey, users, account,
  timeout } }` (`Leafnodes::users`, `Leafnodes::auth_timeout`), each into
  its account, else those of its clients, and answers others with
  `Authorization Violation` or `Authentication Timeout`. A leaf counts as
  linked once the hub took it in.
- `naq`: permissions on naq links, as `nats-server` applies them on leaf
  links. A leaf's `deny_exports` and `deny_imports` hold back what it sends
  and takes, and the interest it tells of and takes; the hub learns its
  `deny_imports` (`peer::Connect::deny_pub`). A hub gives a leaf what its
  user may subscribe to, and takes what it may publish. A leaf with
  `request_isolation` (`peer::Connect::isolate`) hears of no interest of
  the hub's other leafs and hubs; `/leafz` shows it as isolated, and lists
  only the interest a link takes.
- `naq`: `/leafz` counts the messages and bytes each naq link took and
  sent since it linked, summed over the lanes.
- `naq`: `exports` and `imports` of `accounts` (`Account`, `Export`,
  `Import`): streams and services, `accounts`, `account_token_position`,
  `response_type`, `response_threshold`, `prefix`, `to` with `$N` and
  `{{wildcard(N)}}`, `share`. They are checked at start as `nats-server`
  checks them: an import its export does not allow, one that closes a
  cycle, one twice, and a `to` that cannot map are an error.
  `allow_trace: true` is refused. `Options::accounts` holds `Account`s.
- `naq`: stream imports. A subscription in the importer gets a shadow in
  the exporter, on the exporter's subject, as in `nats-server`: the
  exporter's messages reach it with their subject rewritten, its queue
  group is one with the exporter's of the same name, and `UNSUB` maximums
  count direct deliveries only.
- `naq-proto`: `subject::is_subset` and `subject::collide`, for filters
  that hold or meet others.
- `naq`: service imports. A request to an imported service goes on into
  the exporting account with a reply of the server's (`_R_.` and two
  tokens) and a `Nats-Request-Info` header: the requester's account and
  round trip, with `share` its details too, as `nats-server` sends it.
  Responses go back by that reply: one for a `singleton` service, any
  number for `stream` and `chunked` ones until an empty one, all until the
  response threshold. Imports chain, each naming the service on the way;
  a request nobody gets is answered with no responders and the importer's
  subject. Messages that came through a service import skip stream
  imports of the account. At most 262144 requests wait per account.
- `naq`: imports across the cluster and links, as `nats-server` carries
  them. Routes hear of shadows and of the reply subjects of service
  imports, not of import subscriptions; links hear of all three. Requests
  from Go hubs and naq links go through service imports, responses from
  routes too. The interest of a Go hub or a naq hub or leaf bound to an
  importer gets shadows, so imported streams reach it with its subjects;
  queue groups of naq links get none.
- `naq`: a system account (`system_account`, `no_system_account`,
  `Options::system_account`): `$SYS` unless another is named or none is
  wanted, as in `nats-server`; `/varz` names it.
- `naq`: service latency (`latency`), with a system account: a sampled
  request, by its export's share or by its trace headers (Jaeger, B3, W3C
  trace context), gets a reply that ends in the server's hash and `T`, and
  a sample goes to the export's subject once it is answered (200), and when
  it had no reply (400), nobody took it (503) or no response came in time
  (504), as `nats-server` writes it. Samples of requests answered at
  another server carry no responder.
- `naq`: operator mode (`operator`, `trusted_keys`, `resolver: MEMORY`,
  `resolver_preload`; `Options::operators`, `Options::trusted_keys`,
  `Options::resolver`, `Options::resolver_preload`). Accounts are the JWTs
  preloaded, checked as nats-io/jwt checks them; users log in with a user
  JWT and the nonce signed, or as bearer users, and are checked as
  `nats-server` checks them: issuer and signing keys, scoped signing keys
  and their templates, expiry, revocations, `disallow_bearer`, connection
  types, `src`, `times` (UTC only), and the account's and user's limits on
  connections, subscriptions and payload, which left out are zero. A user
  is closed once its JWT expires. Account JWTs import and export as the
  config does, with activation tokens for exports that need them; an
  import that does not link is left out. Accounts with subject mappings or
  auth callout are refused, and v1 JWTs are not taken.
- `naq`: TLS clients log in as the users their certificates name
  (`verify_and_map`; `Tls::map`), on the client and WebSocket listeners,
  as `nats-server` maps them: by e-mail address, DNS name or URI, then
  the subject as a DN, in order or not, then as text with domain
  components and without. A user with no password that a listener maps
  logs in elsewhere with a certificate only.
- `naq`: users of lists may be limited to kinds of connection
  (`allowed_connection_types`; `User::connection_types`,
  `ConnectionType`): `STANDARD`, `WEBSOCKET` and `LEAFNODE` for naq links
  are served; unknown kinds are a config error.
- `naq`: an NKey in a `CONNECT` is passed over where no user has one, as
  in `nats-server`, so the user and password log in.
- `naq`: auth callout (`authorization { auth_callout }`;
  `Options::auth_callout`, `AuthCallout`), and in operator mode accounts
  whose JWT names auth users. A client that is no auth user goes to the
  service: a request the server signs, on `$SYS.REQ.USER.AUTH` in the
  callout account, sealed with `xkey` if given, and the answer puts it in
  an account with permissions, or keeps it out. Answers are checked as
  `nats-server` checks them; the service may be at another server of the
  cluster. The first answer counts. A client that acts before its
  `CONNECT`, or fails its own checks in operator mode, is refused without
  a callout; naq links never call out. A callout without a system
  account, or naming unknown accounts or auth users, is refused at start.
- `naq`: account JWT updates in operator mode, on
  `$SYS.REQ.ACCOUNT.<id>.CLAIMS.UPDATE` and `$SYS.ACCOUNT.<id>.CLAIMS.UPDATE`
  in the system account, answered as `nats-server` answers them with a
  memory resolver: an account a client used takes the update, others skip
  it. The account's clients, at any server of the cluster, check
  themselves again: the newest past a lower connection limit go, new
  subscription and payload limits hold, users of default permissions take
  the new ones and lose the subscriptions they forbid, and revoked users,
  bearer users the account refuses and users of a signing key it dropped
  or changed go. Clients go when their account expires. Imports and
  exports of an account stay as they were at start.
- `naq`: full and cache resolvers (`resolver { type: full|cache, dir }`;
  `Resolver::Full`, `Resolver::Cache`, `Directory`, `Delete`), as
  `nats-server` keeps them: one `<key>.jwt` file per account, with
  `allow_delete`, `hard_delete`, `limit`, `interval`, `ttl` and `timeout`.
  A client of an account the server lacks waits while the account is
  fetched, from the directory or else from the other servers of the
  cluster over `$SYS.REQ.ACCOUNT.<id>.CLAIMS.LOOKUP`, with the accounts
  it imports from; its imports then link and work. The system account
  answers `$SYS.REQ.CLAIMS.UPDATE`, the two update subjects, `LOOKUP`,
  `PACK`, `LIST` and `DELETE` as `nats-server` does; a full resolver asks
  the others for the JWTs it lacks every `interval`, a cache keeps those
  in use up to its limit, and expired JWTs go. A deleted account's
  clients go. Accounts may be added while the server runs, also for the
  interest of other servers in an account this one lacks.
- `naq`: the server ID is the server's NKey, and `INFO` tells its curve
  key (`xkey`), as in `nats-server`. With TLS, clients have the TLS
  timeout and a second to log in, unless `authorization { timeout }` says
  otherwise.
- `naq`: clients may not publish to `_GR_.`, `$GR.` or `$NRG.` subjects,
  nor with `_R_.`, `$JS.ACK.`, `_GR_.` or `$GR.` replies, as in
  `nats-server`: the message is dropped with a permissions violation.
- `naq-bench`: cluster workloads in `naq_suite` (`cluster-one-to-one`,
  `cluster-fan-out-3`, `cluster-queue-3`): three servers of one cluster
  per run, from the same configuration file for `nats-server` and naq
  (`--cluster-port`), the publisher on the first, subscribers on the
  others first. `naq_load` takes `--sub-addr` for the subscribers'
  servers and sums the CPU of each `--server-pid`; before the run, each
  publisher sends probes until they reach the subscribers, so their
  interest has reached its server.

### Changed

- `naq-proto`: `client::parse` reads the usual `PUB`, one space before
  each argument, in one pass, at half the cost; anything else goes the
  general way, with the same result.
- `naq`: a lane fills its clients' read buffers again once no batch for
  another lane refers to them, instead of allocating new ones; a batch
  for another lane starts at the size of the last.
- `naq`: batches for other servers fill the lane's buffers again once
  sent, at the room of the last, instead of new allocations that each
  page faulted in. Fan-out of 1 KiB messages across a cluster of three
  went from 1.1M to 3.3M deliveries a second.

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
- `naq`: a naq leaf closes all its channels to a hub once the link is gone,
  not only those it sends on; the others dialed the hub on and on.
- `naq`: a queue group's message goes to a member a route has for its
  leafs only when no member elsewhere takes it, as in `nats-server`; such
  members had counted as the route's own.
