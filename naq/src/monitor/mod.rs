//! Monitoring over HTTP or HTTPS, as `nats-server` serves it: its
//! endpoints under `http_base_path`, their options, and its JSON.

mod accountz;
mod accstatz;
mod conns;
mod connz;
mod http;
pub(crate) mod json;
mod links;
mod pages;
pub(crate) mod query;
mod routes;
mod statsz;
mod subsz;
mod varz;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use sha2::Digest as _;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use zzq_tokio::transport::{Listener, Stream};

pub(crate) use accountz::{in_use, name_tag};
pub(crate) use accstatz::{conns, statz};
pub(crate) use conns::{closed, link_closed};
pub(crate) use pages::health;
pub(crate) use statsz::{ServerStats, statsz};

use crate::lane::{Control, Lane};
use crate::server::Shared;
use crate::{Error, Options};
use http::{Request, Response};
use query::{Query, Refused};

/// How long a TLS handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The endpoints whose requests `http_req_stats` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counted {
    Root,
    Varz,
    Connz,
    Routez,
    Gatewayz,
    Leafz,
    Subsz,
    Accountz,
    Accstatz,
    Jsz,
    Healthz,
}

impl Counted {
    const ALL: [Counted; 11] = [
        Counted::Root,
        Counted::Varz,
        Counted::Connz,
        Counted::Routez,
        Counted::Gatewayz,
        Counted::Leafz,
        Counted::Subsz,
        Counted::Accountz,
        Counted::Accstatz,
        Counted::Jsz,
        Counted::Healthz,
    ];

    /// Its key in `http_req_stats`.
    const fn key(self) -> &'static str {
        match self {
            Counted::Root => "/",
            Counted::Varz => "/varz",
            Counted::Connz => "/connz",
            Counted::Routez => "/routez",
            Counted::Gatewayz => "/gatewayz",
            Counted::Leafz => "/leafz",
            Counted::Subsz => "/subsz",
            Counted::Accountz => "/accountz",
            Counted::Accstatz => "/accstatz",
            Counted::Jsz => "/jsz",
            Counted::Healthz => "/healthz",
        }
    }
}

/// A configuration as loaded.
#[derive(Debug, Clone)]
pub(crate) struct Loaded {
    /// `sha256:` and the hex SHA-256 of the configuration file; empty
    /// without one.
    pub(crate) digest: String,
    /// When.
    pub(crate) at: SystemTime,
}

/// The digest of the configuration file of `opts`, as `Loaded` keeps it.
fn digest(opts: &Options) -> String {
    opts.config_file
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| format!("sha256:{}", hex(&sha2::Sha256::digest(b))))
        .unwrap_or_default()
}

/// The TLS of the HTTPS port, if it has one.
#[derive(Default)]
struct HttpsTls(std::sync::RwLock<Option<tokio_rustls::TlsAcceptor>>);

impl std::fmt::Debug for HttpsTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTls").finish_non_exhaustive()
    }
}

/// What monitoring keeps for a server.
#[derive(Debug)]
pub(crate) struct State {
    /// Requests per endpoint, by [`Counted`].
    requests: [AtomicU64; Counted::ALL.len()],
    /// The path the endpoints are under, cleaned: `/` by default.
    base: String,
    /// Where monitoring is served over HTTP, if it is.
    http: Option<SocketAddr>,
    /// Where monitoring is served over HTTPS, if it is.
    https: Option<SocketAddr>,
    /// The TLS of the HTTPS port: a reload swaps it.
    tls: HttpsTls,
    /// The configuration, as last loaded.
    loaded: Mutex<Loaded>,
    /// The ports the cluster and naq leafs were bound at, once they are.
    pub(crate) mesh: OnceLock<crate::mesh::Bound>,
    /// The process's CPU time at the last sample.
    cpu: Mutex<Option<varz::Cpu>>,
    /// The connections that closed last.
    closed: conns::Closed,
    /// What the connections of each account that closed did.
    gone: accstatz::Gone,
}

impl State {
    /// The state of a server with `opts`, loaded at `now`, serving
    /// monitoring at `at` if anywhere.
    pub(crate) fn new(opts: &Options, now: SystemTime, at: Option<SocketAddr>) -> State {
        let secure = opts.https_port.is_some();
        State {
            requests: std::array::from_fn(|_| AtomicU64::new(0)),
            base: base_path(&opts.http_base_path),
            http: at.filter(|_| !secure),
            https: at.filter(|_| secure),
            tls: HttpsTls::default(),
            loaded: Mutex::new(Loaded {
                digest: digest(opts),
                at: now,
            }),
            mesh: OnceLock::new(),
            cpu: Mutex::new(None),
            closed: conns::Closed::new(opts.max_closed_clients),
            gone: accstatz::Gone::default(),
        }
    }

    /// The configuration, as last loaded.
    pub(crate) fn loaded(&self) -> Loaded {
        self.loaded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Notes that `opts` were loaded now, as a reload took them. Returns
    /// how the reload logs their digest: `(sha256:...)`, or nothing
    /// without a configuration file.
    pub(crate) fn reloaded(&self, opts: &Options) -> String {
        let digest = digest(opts);
        let shown = if digest.is_empty() {
            String::new()
        } else {
            format!("({digest})")
        };
        *self.loaded.lock().unwrap_or_else(PoisonError::into_inner) = Loaded {
            digest,
            at: SystemTime::now(),
        };
        shown
    }

    /// The TLS of the HTTPS port, if it has one.
    fn tls(&self) -> Option<tokio_rustls::TlsAcceptor> {
        self.tls
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes `tls` for the HTTPS port from now on.
    pub(crate) fn set_tls(&self, tls: Option<tokio_rustls::TlsAcceptor>) {
        *self.tls.0.write().unwrap_or_else(PoisonError::into_inner) = tls;
    }

    /// Where monitoring is served, over HTTP or HTTPS, if it is.
    pub(crate) fn addr(&self) -> Option<SocketAddr> {
        self.http.or(self.https)
    }

    fn count(&self, e: Counted) {
        // Relaxed: a counter, read now and then.
        self.requests[e as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a request of `q` to `e`, if it came over HTTP.
    fn asked(&self, q: &Query, e: Counted) {
        if q.http {
            self.count(e);
        }
    }

    /// `http_req_stats`: the requests of each endpoint asked so far.
    fn stats(&self) -> BTreeMap<&'static str, u64> {
        Counted::ALL
            .iter()
            .map(|&e| (e.key(), self.requests[e as usize].load(Ordering::Relaxed)))
            .filter(|&(_, n)| n > 0)
            .collect()
    }

    /// The page at `path`, if one is there.
    fn page(&self, path: &str) -> Option<Page> {
        let rest = if self.base == "/" {
            path
        } else {
            path.strip_prefix(self.base.as_str())?
        };
        if rest.is_empty() || (rest == "/" && self.base == "/") {
            return Some(Page::Root);
        }
        PAGES
            .iter()
            .find(|(p, _)| *p == rest)
            .map(|&(_, page)| page)
    }
}

/// `p` as `nats-server` takes a base path: rooted and cleaned.
fn base_path(p: &str) -> String {
    let rooted = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };
    http::path_clean(&rooted)
}

/// `bytes` in lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A page of the monitoring port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Root,
    Varz,
    Connz,
    Routez,
    Gatewayz,
    Leafz,
    Subsz,
    Accountz,
    Accstatz,
    Jsz,
    Healthz,
    Ipqueuesz,
    Raftz,
    Expvarz,
}

/// The pages under the base path.
const PAGES: [(&str, Page); 14] = [
    ("/varz", Page::Varz),
    ("/connz", Page::Connz),
    ("/routez", Page::Routez),
    ("/gatewayz", Page::Gatewayz),
    ("/leafz", Page::Leafz),
    ("/subsz", Page::Subsz),
    ("/subscriptionsz", Page::Subsz),
    ("/accountz", Page::Accountz),
    ("/accstatz", Page::Accstatz),
    ("/jsz", Page::Jsz),
    ("/healthz", Page::Healthz),
    ("/ipqueuesz", Page::Ipqueuesz),
    ("/raftz", Page::Raftz),
    ("/debug/vars", Page::Expvarz),
];

/// Checks the monitoring options of `opts`, as `nats-server` does when it
/// starts monitoring.
pub(crate) fn validate(opts: &Options) -> Result<(), Error> {
    if let (Some(http), Some(https)) = (opts.http_port, opts.https_port) {
        return Err(Error::Options(format!(
            "can't specify both HTTP ({http}) and HTTPs ({https}) ports"
        )));
    }
    if opts.https_port.is_some() && opts.tls.is_none() {
        return Err(Error::Options("TLS cert and key required for HTTPS".into()));
    }
    Ok(())
}

/// TLS for the HTTPS port: the server's certificate, and no client
/// certificates asked for.
pub(crate) fn acceptor(opts: &Options) -> Result<Option<tokio_rustls::TlsAcceptor>, Error> {
    match (&opts.tls, opts.https_port) {
        (Some(t), Some(_)) => crate::tls::plain_acceptor(t).map(Some),
        _ => Ok(None),
    }
}

/// Serves monitoring on `listener`, over TLS if `tls` is set, until it
/// closes or the server stops.
pub(crate) async fn serve(mut listener: Listener, shared: Arc<Shared>) {
    loop {
        let stream = match listener.accept().await {
            Ok(s) => s,
            Err(zzq_tokio::Error::Closed) => return,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if crate::stop::stopping(&shared) {
            return;
        }
        let Stream::Tcp(s) = stream else { continue };
        let (shared, tls) = (shared.clone(), shared.monitor.tls());
        tokio::task::spawn_local(async move {
            if s.set_nonblocking(true).is_err() {
                return;
            }
            let Ok(tcp) = tokio::net::TcpStream::from_std(s) else {
                return;
            };
            let pages = Pages { shared };
            match tls {
                None => http::serve(tcp, &pages).await,
                Some(acc) => secure(tcp, &acc, &pages).await,
            }
        });
    }
}

/// Serves `pages` over TLS on `tcp`, after the handshake. A client that
/// speaks plain HTTP gets Go's answer.
async fn secure(mut tcp: tokio::net::TcpStream, acc: &tokio_rustls::TlsAcceptor, pages: &Pages) {
    let mut first = [0u8; 5];
    let peeked = tokio::time::timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first)).await;
    if matches!(peeked, Ok(Ok(5))) && looks_like_http(first) {
        let _ = tcp
            .write_all(b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
            .await;
        return;
    }
    if let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acc.accept(tcp)).await {
        http::serve(tls, pages).await;
    }
}

/// Whether the first bytes of a TLS record are those of an HTTP request,
/// as Go's `tlsRecordHeaderLooksLikeHTTP` takes them.
const fn looks_like_http(head: [u8; 5]) -> bool {
    matches!(&head, b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO")
}

/// The pages of a server's monitoring port.
struct Pages {
    shared: Arc<Shared>,
}

impl http::Handler for Pages {
    async fn answer(&self, req: &Request) -> Response {
        let s = &*self.shared;
        let Some(page) = s.monitor.page(&req.path) else {
            return Response::not_found();
        };
        let q = Query::parse(&req.query);
        let done = match page {
            Page::Root => {
                s.monitor.count(Counted::Root);
                Ok(pages::index(s))
            }
            Page::Varz => {
                s.monitor.count(Counted::Varz);
                Ok(varz::answer(s).await)
            }
            Page::Connz => connz::answer(s, &q).await,
            Page::Routez => routes::answer(s, &q).await,
            Page::Gatewayz => {
                s.monitor.count(Counted::Gatewayz);
                pages::gatewayz(s, &q)
            }
            Page::Leafz => {
                s.monitor.count(Counted::Leafz);
                links::answer(s, &q).await
            }
            Page::Subsz => subsz::answer(s, &q).await,
            Page::Accountz => accountz::answer(s, &q).await,
            Page::Accstatz => accstatz::answer(s, &q).await,
            Page::Jsz => {
                s.monitor.count(Counted::Jsz);
                pages::jsz(s, &q)
            }
            Page::Healthz => {
                s.monitor.count(Counted::Healthz);
                pages::healthz(s, &q)
            }
            Page::Ipqueuesz => pages::ipqueuesz(&q),
            Page::Raftz => Ok(Response::text(404, "No Raft nodes registered")),
            Page::Expvarz => Ok(pages::expvar()),
        };
        done.unwrap_or_else(|refused| Response::text(400, refused))
    }
}

/// JSON of `v`, indented, as an answer.
fn pretty<T: serde::Serialize>(v: &T) -> Response {
    Response::json(200, json::pretty(v))
}

/// An endpoint whose data a `$SYS` request may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shown {
    Varz,
    Connz,
    Routez,
    Gatewayz,
    Leafz,
    Subsz,
    Accountz,
    Jsz,
}

/// What endpoint `e` shows for `q`, as `nats-server` puts it into a
/// `$SYS` answer: compact, in the same order. Or why it cannot.
pub(crate) async fn shown(shared: &Shared, e: Shown, q: &Query) -> Result<Vec<u8>, Refused> {
    let r = match e {
        Shown::Varz => varz::answer(shared).await,
        Shown::Connz => connz::answer(shared, q).await?,
        Shown::Routez => routes::answer(shared, q).await?,
        Shown::Gatewayz => pages::gatewayz(shared, q)?,
        Shown::Leafz => links::answer(shared, q).await?,
        Shown::Subsz => subsz::answer(shared, q).await?,
        Shown::Accountz => accountz::answer(shared, q).await?,
        Shown::Jsz => pages::jsz(shared, q)?,
    };
    // The endpoints write JSON: it reads back.
    let data: json::Ordered = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
    Ok(json::compact(&data))
}

/// What `f` finds on every lane, in lane order. A lane that stopped finds
/// nothing.
pub(crate) async fn ask_all<T, F>(shared: &Shared, f: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(&Lane) -> T + Clone + Send + 'static,
{
    let waits: Vec<_> = (0..shared.lanes.len())
        .map(|i| {
            let (tx, rx) = oneshot::channel();
            let f = f.clone();
            shared.lanes[i].control(Control::Ask(Ask(Box::new(move |lane| {
                let _ = tx.send(f(lane));
            }))));
            rx
        })
        .collect();
    let mut all = Vec::with_capacity(waits.len());
    for w in waits {
        if let Ok(t) = w.await {
            all.push(t);
        }
    }
    all
}

/// What `f` finds on lane `lane` of `shared`'s server; `None` if the lane
/// stopped.
pub(crate) async fn ask<T: Send + 'static>(
    shared: &Shared,
    lane: usize,
    f: impl FnOnce(&Lane) -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    on_lane(shared, lane, move |lane| {
        let _ = tx.send(f(lane));
    });
    rx.await.ok()
}

/// Hands `f` to lane `lane` of `shared`'s server, to run there. A lane
/// that stopped drops it.
pub(crate) fn on_lane(shared: &Shared, lane: usize, f: impl FnOnce(&Lane) + Send + 'static) {
    if let Some(tx) = shared.lanes.get(lane) {
        tx.control(Control::Ask(Ask(Box::new(f))));
    }
}

/// Work monitoring hands a lane: it runs there, and sends what it finds
/// back.
pub(crate) struct Ask(Box<dyn FnOnce(&Lane) + Send>);

impl Ask {
    /// Runs it on `lane`.
    pub(crate) fn run(self, lane: &Lane) {
        (self.0)(lane);
    }
}

impl std::fmt::Debug for Ask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ask")
    }
}

/// Reads `data` as a request to the monitoring port, and as a base path.
///
/// # Panics
///
/// When a cleaned path or base path is not clean.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    http::fuzz(data);
    let base = base_path(&String::from_utf8_lossy(data));
    assert_eq!(http::path_clean(&base), base, "{base:?} is not clean");
}

/// What `/accountz` shows of account `name` in detail, as `nats-server`
/// answers a `$SYS` `INFO` request: compact. Or why it cannot.
pub(crate) async fn account_info(shared: &Shared, name: &str) -> Result<Vec<u8>, Refused> {
    let q = Query::of_pairs(vec![("acc".into(), name.into())]);
    let r = accountz::answer(shared, &q).await?;
    // The endpoint writes JSON: it reads back.
    let page: json::Ordered = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
    let json::Ordered::Object(fields) = page else {
        return Err(format!("Account {name} does not exist"));
    };
    fields
        .into_iter()
        .find(|(k, _)| k == "account_detail")
        .map(|(_, d)| json::compact(&d))
        .ok_or_else(|| format!("Account {name} does not exist"))
}

/// Text of `b`, as monitoring shows bytes it holds.
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A round trip as `nats-server` shows it: to the microsecond between
/// one and a thousand of them, else to the nanosecond.
fn rtt(d: Duration) -> String {
    crate::times::go_duration(crate::times::go_rtt(d))
}

/// Now, as a time to show.
fn now() -> String {
    crate::times::rfc3339_nano(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_sit_under_the_base_path() {
        let state = |base: &str| {
            State::new(
                &Options {
                    http_base_path: base.into(),
                    ..Options::default()
                },
                SystemTime::now(),
                None,
            )
        };
        let root = state("");
        assert_eq!(root.page("/"), Some(Page::Root));
        assert_eq!(root.page("/varz"), Some(Page::Varz));
        assert_eq!(root.page("/subscriptionsz"), Some(Page::Subsz));
        assert_eq!(root.page("/varz/"), None);
        assert_eq!(root.page("/VARZ"), None);
        let under = state("mon/x/");
        assert_eq!(under.base, "/mon/x");
        assert_eq!(under.page("/mon/x"), Some(Page::Root));
        assert_eq!(under.page("/mon/x/"), None);
        assert_eq!(under.page("/mon/x/connz"), Some(Page::Connz));
        assert_eq!(under.page("/varz"), None);
        assert_eq!(under.page("/mon/xvarz"), None);
        assert_eq!(base_path("/a/../b//c"), "/b/c");
    }

    #[test]
    fn requests_are_counted_by_endpoint() {
        let s = State::new(&Options::default(), SystemTime::now(), None);
        assert!(s.stats().is_empty());
        s.count(Counted::Varz);
        s.count(Counted::Varz);
        s.count(Counted::Root);
        let stats: Vec<_> = s.stats().into_iter().collect();
        assert_eq!(stats, [("/", 1), ("/varz", 2)]);
        for e in Counted::ALL {
            assert!(e.key().starts_with('/'));
        }
    }

    #[test]
    fn round_trips_are_cut_to_microseconds_below_a_millisecond() {
        assert_eq!(rtt(Duration::from_nanos(433_712)), "433\u{b5}s");
        assert_eq!(rtt(Duration::from_nanos(1_271_087)), "1.271087ms");
        assert_eq!(rtt(Duration::from_nanos(999)), "999ns");
        assert_eq!(rtt(Duration::ZERO), "0s");
    }

    #[test]
    fn https_looks_for_plain_http() {
        assert!(looks_like_http(*b"GET /"));
        assert!(!looks_like_http([0x16, 3, 1, 0, 1]));
        assert_eq!(hex(&[0, 0xab]), "00ab");
        assert_eq!(format!("{:?}", Ask(Box::new(|_| {}))), "Ask");
    }

    #[test]
    fn both_ports_or_https_without_tls_are_refused() {
        let both = Options {
            http_port: Some(1),
            https_port: Some(2),
            ..Options::default()
        };
        assert!(
            matches!(validate(&both), Err(Error::Options(e)) if e == "can't specify both HTTP (1) and HTTPs (2) ports")
        );
        let bare = Options {
            https_port: Some(2),
            ..Options::default()
        };
        assert!(
            matches!(validate(&bare), Err(Error::Options(e)) if e == "TLS cert and key required for HTTPS")
        );
        assert!(validate(&Options::default()).is_ok());
    }
}
