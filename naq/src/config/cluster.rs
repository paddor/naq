//! The `cluster` block: the other naq servers of a fixed mesh.

use super::parse::{Item, Value};
use super::{Bad, int, listen, string};
use crate::Cluster;

/// `cluster { name, listen, host, port, routes }`.
pub(super) fn cluster(item: &Item) -> Result<Cluster, Bad> {
    let Value::Map(m) = &item.value else {
        return Err((item.line, "cluster: expected a map".into()));
    };
    let mut c = Cluster::default();
    for (k, v) in m {
        let k = k.to_ascii_lowercase();
        let bad = |reason: &str| (v.line, format!("cluster: {k}: {reason}"));
        match k.as_str() {
            "name" => c.name = string(v).ok_or_else(|| bad("expected a string"))?,
            "listen" => {
                let (host, port) = listen(v).ok_or_else(|| bad("expected host:port"))?;
                if let Some(h) = host {
                    c.host = h;
                }
                c.port = port;
            }
            "host" | "net" => c.host = string(v).ok_or_else(|| bad("expected a string"))?,
            "port" => c.port = int(v).ok_or_else(|| bad("expected a port"))?,
            "routes" => match &v.value {
                Value::Str(s) => c.routes.push(s.clone()),
                Value::Array(a) => {
                    for u in a {
                        c.routes
                            .push(string(u).ok_or_else(|| bad("expected strings"))?);
                    }
                }
                _ => return Err(bad("expected a string or a list")),
            },
            _ => return Err(bad("not supported")),
        }
    }
    Ok(c)
}
