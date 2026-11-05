//! Seeds for every target, from inputs the server meets.

/// The seeds of target `name`.
#[must_use]
pub fn for_target(name: &str) -> Vec<Vec<u8>> {
    let list: &[&str] = match name {
        "client_wire" => &[
            "CONNECT {\"verbose\":false,\"headers\":true}\r\nPING\r\n",
            "PUB greet 5\r\nhello\r\nPUB greet reply.to 0\r\n\r\n",
            "HPUB h r 18 20\r\nNATS/1.0\r\nA: B\r\n\r\nhi\r\n",
            "SUB foo.* q 1\r\nSUB > 2\r\nUNSUB 1 5\r\nUNSUB 2\r\n",
            "sub foo 1\r\npub foo 2\r\nhi\r\nping\r\npong\r\n",
            "PUB a 3\r\nab",
            "FOO\r\n",
        ],
        "config" => &[
            "listen: 127.0.0.1:4222\nmax_payload: 1MB\nping_interval: \"2m\"\n",
            "authorization {\n  users: [{user: a, password: p, permissions: {publish: {allow: [\"a.>\"], deny: a.b}}}]\n}\n",
            "accounts { A { users: [{user: x, password: y}] } }\nno_auth_user: x\n",
            "tls { cert_file: a.pem, key_file: b.pem, timeout: 0.5 }\nhttp_port: 8222\n",
            "a = [1, 2k, 3MB, -4, 1.5, yes, 'q', \"e\\t\"]\nb { c: $a }\n",
            "leafnodes { reconnect: 2s, remotes: [{url: \"nats-leaf://h:7422\", creds: u.creds}, {urls: [a], seed: SUA, account: A, tls { ca_file: c.pem, timeout: 1.5, handshake_first: true }}] }\n",
            "cluster { name: c, listen: \"127.0.0.1:6222\", routes: [\"nats-route://a:6222\", b] }\n",
        ],
        "leaf_wire" => &[
            "INFO {\"server_id\":\"h\",\"nonce\":\"abc\",\"info_on_connect\":true} \r\nPING\r\n",
            "LS+ foo\r\nLS+ bar.* q 3\r\nLS- bar.* q\r\nLS- foo\r\nLS+ $LDS.xyz\r\n",
            "LMSG foo 2\r\nhi\r\nLMSG foo r 0\r\n\r\nLMSG foo | q1 q2 2\r\nhi\r\n",
            "LMSG foo + _INBOX.1 q 2\r\nhi\r\nHMSG h | q 12 14\r\nNATS/1.0\r\n\r\nhi\r\n",
            "-ERR 'Loop detected for leafnode account=\"$G\". Delaying attempt to reconnect for 30s'\r\n+OK\r\nPONG\r\n",
            "CONNECT {\"name\":\"leaf\",\"headers\":true}\r\nLMSG a 3\r\nab",
            "LS+ s q\r\n",
        ],
        "subjects" => &[
            "a.b.c\na.b.c\na.*.c\na.>\n>\nb.*\n*.*.*\n",
            "orders.1\norders.*\norders.>\n*.1\n",
            "x\n*\n>\nx.y\n",
        ],
        "websocket" => return websocket(),
        "peer_frames" => return peer_frames(),
        _ => &[],
    };
    list.iter().map(|s| s.as_bytes().to_vec()).collect()
}

const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: a.example\r\nOrigin: http://a.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\nCookie: u=al; p=pw\r\n\r\n";

/// Upgrades, then frames: data, fragments, control, compressed and broken.
fn websocket() -> Vec<Vec<u8>> {
    let frames: [&[u8]; 5] = [
        b"\x82\x86\0\0\0\0PING\r\n",
        b"\x01\x83\x01\x02\x03\x04QKJ\x89\x81\0\0\0\0p\x80\x83\0\0\0\0G\r\n",
        b"\xc2\x88\0\0\0\0\x0a\xf0\xf4\x73\xe7\xe5\x02\x00",
        b"\x88\x85\0\0\0\0\x03\xe8bye",
        b"\x82\x06PING\r\n\x83\x80\0\0\0\0",
    ];
    let mut seeds: Vec<Vec<u8>> = frames
        .iter()
        .map(|f| [UPGRADE.as_bytes(), f].concat())
        .collect();
    seeds.push(b"POST /mqtt HTTP/1.1\r\nHost: a\r\n\r\n".to_vec());
    seeds.push(b"\x16\x03\x01\x02\x00\x01\n".to_vec());
    seeds
}

/// Peer control messages of every kind, and a batch.
fn peer_frames() -> Vec<Vec<u8>> {
    use naq_proto::peer::{self, Control, Hello, Interest, Record, Role};
    let i = Interest {
        account: b"$G",
        subject: b"a.*",
        queue: Some(b"q"),
        weight: 2,
        origin: Some(b"o"),
    };
    let controls = [
        Control::Hello(Hello {
            role: Role::Leaf,
            account: b"A",
            epoch: 1,
            server_id: b"N1",
            name: b"a",
            cluster: b"c",
            data: b"tcp://127.0.0.1:1",
            client_urls: b"127.0.0.1:4222",
            leaf_urls: b"",
        }),
        Control::SnapshotStart { epoch: 1, seq: 0 },
        Control::Entry(i),
        Control::SnapshotEnd { epoch: 1 },
        Control::Delta {
            epoch: 1,
            seq: 1,
            interest: i,
        },
        Control::Beat { epoch: 1, seq: 1 },
        Control::Resync,
    ];
    let mut all: Vec<Vec<u8>> = controls
        .iter()
        .map(|c| {
            let mut out = Vec::new();
            c.encode(&mut out);
            out
        })
        .collect();
    let mut batch = Vec::new();
    peer::batch(&mut batch, Some(b"o"), b"$G");
    Record {
        subject: b"a.b",
        reply: Some(b"r"),
        headers: Some(b"NATS/1.0\r\n\r\n"),
        payload: b"hi",
        queue: Some(b"q"),
    }
    .encode(&mut batch);
    all.push(batch);
    all
}
