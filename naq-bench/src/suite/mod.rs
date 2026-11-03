//! The benchmark suite: the same load against `nats-server` and naq.
//!
//! Every run gets a fresh server on the server CPUs and a `naq_load`
//! process on the load CPUs. Repetitions alternate which server goes first
//! (A B, then B A), so a machine that drifts hurts both alike. The gate
//! compares naq with the rival measured in the same session: the ratio of
//! the medians must not fall below a floor.

mod host;
mod report;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

pub use report::{Row, Stats, Status, Verdict, rows, table, verdict};

/// A load shape: connections and their subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Workload {
    /// Label in records and the table.
    pub name: &'static str,
    /// Publisher connections.
    pub pubs: usize,
    /// Subscriber connections. Zero publishes only.
    pub subs: usize,
    /// Queue group the subscribers join.
    pub queue: Option<&'static str>,
    /// Payload sizes measured.
    pub payloads: &'static [usize],
}

/// The workloads, as in the baseline.
pub const WORKLOADS: [Workload; 4] = [
    Workload {
        name: "one-to-one",
        pubs: 1,
        subs: 1,
        queue: None,
        payloads: &[16, 64, 1024],
    },
    Workload {
        name: "fan-out-4",
        pubs: 1,
        subs: 4,
        queue: None,
        payloads: &[16, 1024],
    },
    Workload {
        name: "queue-4",
        pubs: 1,
        subs: 4,
        queue: Some("q"),
        payloads: &[16, 1024],
    },
    Workload {
        name: "pub-only",
        pubs: 1,
        subs: 0,
        queue: None,
        payloads: &[16, 1024],
    },
];

/// A gated cell: naq's rate over the rival's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Gate {
    /// Workload name.
    pub workload: &'static str,
    /// Payload size.
    pub payload: usize,
    /// The ratio must not fall below this.
    pub floor: f64,
    /// The ratio naq aims for.
    pub target: f64,
}

/// The target workloads: one publisher, one subscriber. Floors sit about
/// 10% under the ratios measured when they were set.
pub const GATES: [Gate; 3] = [
    Gate {
        workload: "one-to-one",
        payload: 16,
        floor: 5.1,
        target: 7.0,
    },
    Gate {
        workload: "one-to-one",
        payload: 64,
        floor: 5.3,
        target: 7.0,
    },
    Gate {
        workload: "one-to-one",
        payload: 1024,
        floor: 2.2,
        target: 3.0,
    },
];

/// A workload at one payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// The load shape.
    pub workload: Workload,
    /// Payload bytes per message.
    pub payload: usize,
}

impl Cell {
    /// The gate on this cell, if any.
    pub fn gate(&self) -> Option<&'static Gate> {
        GATES
            .iter()
            .find(|g| g.workload == self.workload.name && g.payload == self.payload)
    }

    /// The rate that counts: delivered, or published without subscribers.
    const fn metric(&self) -> &'static str {
        if self.workload.subs == 0 {
            "pub_msgs_s"
        } else {
            "sub_msgs_s"
        }
    }
}

/// The cells of the named workloads, all if none are named. Only gated
/// cells if `gated`.
///
/// # Errors
///
/// An unknown workload name, or a selection without cells.
pub fn cells(names: &[String], gated: bool) -> Result<Vec<Cell>, String> {
    if let Some(bad) = names
        .iter()
        .find(|n| !WORKLOADS.iter().any(|w| w.name == n.as_str()))
    {
        return Err(format!("unknown workload {bad:?}"));
    }
    let cells: Vec<Cell> = WORKLOADS
        .iter()
        .filter(|w| names.is_empty() || names.iter().any(|n| n == w.name))
        .flat_map(|&workload| {
            workload
                .payloads
                .iter()
                .map(move |&payload| Cell { workload, payload })
        })
        .filter(|c| !gated || c.gate().is_some())
        .collect();
    if cells.is_empty() {
        return Err("no gated cell in these workloads".into());
    }
    Ok(cells)
}

/// A server under test, started as `program -a 127.0.0.1 -p PORT args..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Label in records, logs and the table.
    pub name: String,
    /// The binary.
    pub program: PathBuf,
    /// Arguments after the address flags.
    pub args: Vec<String>,
}

/// Which server of the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The reference server.
    Rival,
    /// naq.
    Naq,
}

/// Runs per cell and their timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Runs per server and cell.
    pub reps: usize,
    /// Before measuring.
    pub warmup: Duration,
    /// Measured.
    pub duration: Duration,
}

/// Where the processes run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// Client port of the servers.
    pub port: u16,
    /// `taskset` CPU list for the servers. Empty: no pinning.
    pub server_cpus: String,
    /// `taskset` CPU list for `naq_load`. Empty: no pinning.
    pub load_cpus: String,
    /// Wait for an idle machine before each run.
    pub idle_check: bool,
}

/// Where the results go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Directory for the server logs.
    pub logs: PathBuf,
    /// File each run's JSON line is appended to.
    pub record: Option<PathBuf>,
    /// Extra labels on every record.
    pub tags: BTreeMap<String, String>,
}

/// A whole session.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// The reference server.
    pub rival: Server,
    /// naq.
    pub naq: Server,
    /// The `naq_load` binary.
    pub load: PathBuf,
    /// Cells, in order.
    pub cells: Vec<Cell>,
    /// Runs and their timing.
    pub timing: Timing,
    /// Ports and CPUs.
    pub host: Host,
    /// Logs and records.
    pub out: Output,
}

impl Plan {
    const fn server(&self, side: Side) -> &Server {
        match side {
            Side::Rival => &self.rival,
            Side::Naq => &self.naq,
        }
    }

    /// `naq_load` arguments for one run.
    fn load_args(&self, cell: &Cell, side: Side, pid: u32, rep: usize) -> Vec<String> {
        let server = self.server(side);
        let w = &cell.workload;
        let mut a: Vec<String> = [
            "--addr",
            &format!("127.0.0.1:{}", self.host.port),
            "--pubs",
            &w.pubs.to_string(),
            "--subs",
            &w.subs.to_string(),
            "--payload",
            &cell.payload.to_string(),
            "--warmup",
            &self.timing.warmup.as_secs_f64().to_string(),
            "--duration",
            &self.timing.duration.as_secs_f64().to_string(),
            "--server",
            &server.name,
            "--server-pid",
            &pid.to_string(),
            "--workload",
            w.name,
        ]
        .map(str::to_owned)
        .into();
        if let Some(q) = w.queue {
            a.extend(["--queue".into(), q.into()]);
        }
        let mut tags = self.out.tags.clone();
        tags.insert("rep".into(), rep.to_string());
        tags.insert("server_args".into(), server.args.join(" "));
        tags.insert("server_cpus".into(), self.host.server_cpus.clone());
        tags.insert("load_cpus".into(), self.host.load_cpus.clone());
        for (k, v) in tags {
            a.extend(["--tag".into(), format!("{k}={v}")]);
        }
        if let Some(r) = &self.out.record {
            a.extend(["--record".into(), r.display().to_string()]);
        }
        a
    }

    /// Longest a load run may take before it counts as hung.
    fn load_limit(&self) -> Duration {
        // naq_load's own drain and handshake limits, plus slack.
        self.timing.warmup + self.timing.duration + Duration::from_secs(30)
    }
}

/// One measured run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Index into the plan's cells.
    pub cell: usize,
    /// Which server.
    pub side: Side,
    /// Repetition.
    pub rep: usize,
    /// Messages per second: delivered, or published without subscribers.
    pub msgs_s: f64,
}

/// A session that cannot go on.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SuiteError {
    /// The machine did not go idle.
    #[error("machine not idle")]
    Busy,
    /// The client port is taken before the server starts.
    #[error("port {0} is in use")]
    PortInUse(u16),
    /// A server did not come up.
    #[error("{name}: {why}, see {}", log.display())]
    Server {
        /// Server label.
        name: String,
        /// What went wrong.
        why: String,
        /// Its log.
        log: PathBuf,
    },
    /// A load run failed, hung or printed no record.
    #[error("naq_load: {0}")]
    Load(String),
    /// Spawning, logs or output.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The server order for a repetition.
const fn order(rep: usize) -> [Side; 2] {
    if rep.is_multiple_of(2) {
        [Side::Rival, Side::Naq]
    } else {
        [Side::Naq, Side::Rival]
    }
}

/// Runs the plan, writing each command and its summary to `out`.
///
/// # Errors
///
/// The first run that fails ends the session.
pub fn run(plan: &Plan, out: &mut dyn Write) -> Result<Vec<Sample>, SuiteError> {
    std::fs::create_dir_all(&plan.out.logs)?;
    let mut samples = Vec::new();
    for (i, cell) in plan.cells.iter().enumerate() {
        for rep in 0..plan.timing.reps {
            for side in order(rep) {
                if plan.host.idle_check {
                    host::wait_idle(out, host::probe)?;
                }
                let msgs_s = measure(plan, cell, side, rep, out)?;
                samples.push(Sample {
                    cell: i,
                    side,
                    rep,
                    msgs_s,
                });
            }
        }
    }
    Ok(samples)
}

/// One run on a fresh server.
fn measure(
    plan: &Plan,
    cell: &Cell,
    side: Side,
    rep: usize,
    out: &mut dyn Write,
) -> Result<f64, SuiteError> {
    let server = plan.server(side);
    let log = plan.out.logs.join(format!(
        "{}-{}-{}-{rep}.log",
        server.name, cell.workload.name, cell.payload
    ));
    let running = host::Running::start(&plan.host, server, &log)?;
    let args = plan.load_args(cell, side, running.pid(), rep);
    let rec = host::load(
        &plan.host.load_cpus,
        &plan.load,
        &args,
        plan.load_limit(),
        out,
    )?;
    drop(running);
    rec[cell.metric()]
        .as_f64()
        .ok_or_else(|| SuiteError::Load(format!("no {} in the record", cell.metric())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        let server = |name: &str| Server {
            name: name.into(),
            program: name.into(),
            args: vec!["--lanes".into(), "2".into()],
        };
        Plan {
            rival: server("nats-server"),
            naq: server("naq"),
            load: "naq_load".into(),
            cells: cells(&[], false).unwrap(),
            timing: Timing {
                reps: 3,
                warmup: Duration::from_millis(500),
                duration: Duration::from_secs(10),
            },
            host: Host {
                port: 4999,
                server_cpus: "0-3".into(),
                load_cpus: "4-5".into(),
                idle_check: true,
            },
            out: Output {
                logs: "logs".into(),
                record: Some("runs.jsonl".into()),
                tags: BTreeMap::from([("commit".into(), "abc".into())]),
            },
        }
    }

    #[test]
    fn cells_follow_the_workloads_and_the_gate() {
        let all = cells(&[], false).unwrap();
        assert_eq!(all.len(), 9);
        assert_eq!((all[0].workload.name, all[0].payload), ("one-to-one", 16));
        let gated = cells(&[], true).unwrap();
        assert_eq!(
            gated.iter().map(|c| c.payload).collect::<Vec<_>>(),
            [16, 64, 1024]
        );
        assert!(gated.iter().all(|c| c.gate().is_some()));
        let some = cells(&["queue-4".into(), "pub-only".into()], false).unwrap();
        assert_eq!(some.len(), 4);
        assert!(some.iter().all(|c| c.gate().is_none()));
        assert_eq!(some[2].metric(), "pub_msgs_s");
        assert_eq!(some[0].metric(), "sub_msgs_s");
        assert!(cells(&["nope".into()], false).is_err());
        assert!(cells(&["pub-only".into()], true).is_err());
    }

    #[test]
    fn every_gate_names_a_cell_and_sits_below_its_target() {
        let all = cells(&[], false).unwrap();
        for g in &GATES {
            assert!(all.iter().any(|c| c.gate() == Some(g)), "{g:?}");
            assert!(g.floor < g.target, "{g:?}");
        }
    }

    #[test]
    fn repetitions_alternate_the_server_order() {
        assert_eq!(order(0), [Side::Rival, Side::Naq]);
        assert_eq!(order(1), [Side::Naq, Side::Rival]);
        assert_eq!(order(2), order(0));
    }

    #[test]
    fn load_arguments_carry_the_cell_the_server_and_the_labels() {
        let p = plan();
        let queue = p.cells.iter().find(|c| c.workload.queue.is_some()).unwrap();
        let a = p.load_args(queue, Side::Naq, 42, 1).join(" ");
        assert!(
            a.starts_with(
                "--addr 127.0.0.1:4999 --pubs 1 --subs 4 --payload 16 --warmup 0.5 \
                 --duration 10 --server naq --server-pid 42 --workload queue-4 --queue q"
            ),
            "{a}"
        );
        assert!(
            a.ends_with(
                "--tag commit=abc --tag load_cpus=4-5 --tag rep=1 --tag server_args=--lanes 2 \
                 --tag server_cpus=0-3 --record runs.jsonl"
            ),
            "{a}"
        );
        let mut bare = p.clone();
        bare.out.record = None;
        let a = bare.load_args(&bare.cells[0], Side::Rival, 1, 0);
        assert!(!a.contains(&"--record".to_owned()) && !a.contains(&"--queue".to_owned()));
        assert_eq!(p.server(Side::Rival).name, "nats-server");
        assert_eq!(p.load_limit(), Duration::from_millis(40_500));
    }
}
