//! Server settings.

/// Server settings. The defaults are those of `nats-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Host to listen on for clients.
    pub host: String,
    /// Port to listen on for clients. 0 picks a free one.
    pub port: u16,
    /// IO lanes, each on a thread of its own. 0 counts as 1.
    pub lanes: usize,
    /// Name in `INFO`.
    pub server_name: String,
    /// Largest message a client may publish, headers included
    /// (`max_payload`).
    pub max_payload: usize,
    /// Longest arguments of a control line (`max_control_line`).
    pub max_control_line: usize,
    /// Most bytes waiting to be written to one client (`max_pending`). Past
    /// three quarters of it, its publishers wait; past it, it is closed as a
    /// slow consumer.
    pub max_pending: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            host: "0.0.0.0".into(),
            port: 4222,
            lanes: 1,
            server_name: "naq".into(),
            max_payload: 1 << 20,
            max_control_line: 4096,
            max_pending: 64 << 20,
        }
    }
}
