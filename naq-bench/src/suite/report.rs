//! Medians, the table and the gate's verdict.

use std::fmt::Write as _;

use super::{Cell, Gate, Sample, Side};

/// Spread above which a gated cell proves nothing.
pub(super) const NOISY: f64 = 0.10;

/// Median and spread of a cell's runs on one server.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    /// Median rate.
    pub median: f64,
    /// Highest minus lowest, over the median.
    pub spread: f64,
}

impl Stats {
    /// The stats of `xs`, `None` if empty.
    pub fn of(xs: &[f64]) -> Option<Stats> {
        let mut v = xs.to_vec();
        v.sort_by(f64::total_cmp);
        let (lo, hi) = (*v.first()?, *v.last()?);
        let n = v.len();
        let median = if n % 2 == 1 {
            v[n / 2]
        } else {
            f64::midpoint(v[n / 2 - 1], v[n / 2])
        };
        let spread = if median > 0.0 {
            (hi - lo) / median
        } else {
            0.0
        };
        Some(Stats { median, spread })
    }
}

/// How a cell stands against its gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No gate on this cell.
    Ungated,
    /// Spread too wide to judge.
    Noisy,
    /// Below the floor.
    Below,
    /// At or above the floor, below the target.
    Pass,
    /// At or above the target.
    Target,
}

/// A cell's result on both servers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Row {
    /// The cell.
    pub cell: Cell,
    /// The reference server.
    pub rival: Stats,
    /// naq.
    pub naq: Stats,
}

impl Row {
    /// naq's median over the rival's.
    pub fn ratio(&self) -> f64 {
        if self.rival.median > 0.0 {
            self.naq.median / self.rival.median
        } else {
            0.0
        }
    }

    /// The wider of the two spreads.
    pub const fn spread(&self) -> f64 {
        self.rival.spread.max(self.naq.spread)
    }

    /// The gate on this row, if any.
    pub fn gate(&self) -> Option<&'static Gate> {
        self.cell.gate()
    }

    /// Where the row stands.
    pub fn status(&self) -> Status {
        let Some(g) = self.gate() else {
            return Status::Ungated;
        };
        let r = self.ratio();
        if self.spread() > NOISY {
            Status::Noisy
        } else if r < g.floor {
            Status::Below
        } else if r < g.target {
            Status::Pass
        } else {
            Status::Target
        }
    }
}

/// One row per cell measured on both servers.
pub fn rows(cells: &[Cell], samples: &[Sample]) -> Vec<Row> {
    cells
        .iter()
        .enumerate()
        .filter_map(|(i, &cell)| {
            let side = |s: Side| {
                let xs: Vec<f64> = samples
                    .iter()
                    .filter(|x| x.cell == i && x.side == s)
                    .map(|x| x.msgs_s)
                    .collect();
                Stats::of(&xs)
            };
            Some(Row {
                cell,
                rival: side(Side::Rival)?,
                naq: side(Side::Naq)?,
            })
        })
        .collect()
}

/// `16 B`, `1 KiB`.
fn size(bytes: usize) -> String {
    if bytes >= 1024 && bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

/// The rows as a table for people: millions of messages per second.
pub fn table(rows: &[Row]) -> String {
    let mut t = String::from(
        "workload    payload  rival msgs/s  naq msgs/s      x  spread  floor  target  status\n",
    );
    for r in rows {
        let (floor, target) = r.gate().map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            |g| (format!("{:.1}", g.floor), format!("{:.1}", g.target)),
        );
        let status = match r.status() {
            Status::Ungated => "-",
            Status::Noisy => "noisy",
            Status::Below => "below floor",
            Status::Pass => "pass",
            Status::Target => "target met",
        };
        let _ = writeln!(
            t,
            "{:<10}  {:>7}  {:>11.3}M  {:>9.3}M  {:>5.2}  {:>5.1}%  {floor:>5}  {target:>6}  {status}",
            r.cell.workload.name,
            size(r.cell.payload),
            r.rival.median / 1e6,
            r.naq.median / 1e6,
            r.ratio(),
            r.spread() * 100.0,
        );
    }
    t
}

/// The gate's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// No gated cell is below its floor or noisy.
    pub passed: bool,
    /// One line for people.
    pub line: String,
}

/// Judges the gated rows.
pub fn verdict(rows: &[Row]) -> Verdict {
    let gated: Vec<&Row> = rows.iter().filter(|r| r.gate().is_some()).collect();
    let failed: Vec<String> = gated
        .iter()
        .filter(|r| matches!(r.status(), Status::Below | Status::Noisy))
        .map(|r| {
            let what = if r.status() == Status::Noisy {
                format!("noisy ({:.1}%)", r.spread() * 100.0)
            } else {
                format!("{:.2}x", r.ratio())
            };
            format!("{} {} {what}", r.cell.workload.name, size(r.cell.payload))
        })
        .collect();
    let met = gated
        .iter()
        .filter(|r| r.status() == Status::Target)
        .count();
    if gated.is_empty() {
        return Verdict {
            passed: true,
            line: "gate: no gated cell measured".into(),
        };
    }
    if failed.is_empty() {
        return Verdict {
            passed: true,
            line: format!("gate: pass, {} of {} cells at target", met, gated.len()),
        };
    }
    Verdict {
        passed: false,
        line: format!("gate: FAIL, {}", failed.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{WORKLOADS, cells};
    use super::*;

    #[test]
    fn stats_take_the_median_and_the_spread() {
        let s = Stats::of(&[3.0, 1.0, 2.0]).unwrap();
        assert_eq!((s.median, s.spread), (2.0, 1.0));
        let s = Stats::of(&[4.0, 2.0]).unwrap();
        assert_eq!((s.median, s.spread), (3.0, 2.0 / 3.0));
        assert_eq!(Stats::of(&[0.0]).unwrap().spread, 0.0);
        assert_eq!(Stats::of(&[]), None);
    }

    fn row(cell: Cell, rival: f64, naq: f64, spread: f64) -> Row {
        Row {
            cell,
            rival: Stats {
                median: rival,
                spread: 0.0,
            },
            naq: Stats {
                median: naq,
                spread,
            },
        }
    }

    #[test]
    fn a_row_stands_against_its_floor_and_target() {
        let all = cells(&[], false).unwrap();
        let (gated, free) = (all[0], all[3]);
        let g = gated.gate().unwrap();
        assert_eq!(row(free, 1.0, 9.0, 0.5).status(), Status::Ungated);
        assert_eq!(row(gated, 1.0, g.floor, 0.2).status(), Status::Noisy);
        assert_eq!(row(gated, 1.0, g.floor - 0.1, 0.0).status(), Status::Below);
        assert_eq!(row(gated, 1.0, g.floor, 0.05).status(), Status::Pass);
        assert_eq!(row(gated, 1.0, g.target, 0.0).status(), Status::Target);
        assert_eq!(row(gated, 0.0, 1.0, 0.0).ratio(), 0.0);
    }

    #[test]
    fn rows_pair_both_servers_and_skip_cells_missing_one() {
        let all = cells(&[], false).unwrap();
        let s = |cell, side, msgs_s| Sample {
            cell,
            side,
            rep: 0,
            msgs_s,
        };
        let samples = [
            s(0, Side::Rival, 2.0),
            s(0, Side::Naq, 10.0),
            s(0, Side::Naq, 14.0),
            s(1, Side::Rival, 1.0),
        ];
        let rows = rows(&all, &samples);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].ratio(), rows[0].spread()), (6.0, 4.0 / 12.0));
    }

    #[test]
    fn the_table_shows_rates_ratios_and_status() {
        let all = cells(&[], false).unwrap();
        let rows = [
            row(all[0], 2e6, 14e6, 0.01),
            row(all[2], 1e6, 2e6, 0.0),
            row(all[3], 1e6, 9e6, 0.0),
        ];
        let t = table(&rows);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(
            lines[1],
            "one-to-one     16 B        2.000M     14.000M   7.00    1.0%    6.9     7.0  target met"
        );
        assert!(lines[2].contains("1 KiB") && lines[2].ends_with("below floor"));
        assert!(lines[3].starts_with("fan-out-4") && lines[3].ends_with("-       -  -"));
    }

    #[test]
    fn the_verdict_fails_on_a_floor_or_noise_only() {
        let all = cells(&[], false).unwrap();
        let g = |i: usize| all[i].gate().unwrap();
        let pass = verdict(&[
            row(all[0], 1.0, g(0).target, 0.0),
            row(all[1], 1.0, g(1).floor, 0.0),
            row(all[3], 1.0, 0.1, 0.0),
        ]);
        assert!(pass.passed);
        assert_eq!(pass.line, "gate: pass, 1 of 2 cells at target");
        let fail = verdict(&[row(all[0], 1.0, 1.0, 0.0), row(all[2], 1.0, 9.0, 0.3)]);
        assert!(!fail.passed);
        assert_eq!(
            fail.line,
            "gate: FAIL, one-to-one 16 B 1.00x, one-to-one 1 KiB noisy (30.0%)"
        );
        let none = verdict(&[row(all[3], 1.0, 1.0, 0.0)]);
        assert!(none.passed && none.line.contains("no gated"));
        assert_eq!(WORKLOADS[3].name, "pub-only");
        assert_eq!(
            (size(16), size(1024), size(1500)),
            ("16 B".into(), "1 KiB".into(), "1500 B".into())
        );
    }
}
