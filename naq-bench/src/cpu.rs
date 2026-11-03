//! Process CPU time from `/proc`.

use std::time::Duration;

/// Clock ticks per second in `/proc` times (`USER_HZ`, 100 on Linux).
const USER_HZ: u64 = 100;

/// User plus system CPU time of process `pid`, or `None` if it cannot be
/// read.
pub fn process_time(pid: u32) -> Option<Duration> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_time(&stat)
}

/// CPU time of this process.
pub fn own_time() -> Option<Duration> {
    process_time(std::process::id())
}

/// Parses `utime + stime` from a `/proc/<pid>/stat` line.
fn stat_time(stat: &str) -> Option<Duration> {
    // The command name may hold spaces; fields restart after ") ".
    let (_, rest) = stat.rsplit_once(") ")?;
    let mut fields = rest.split(' ');
    // `rest` starts at field 3 (state); utime is 14 and stime 15.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    let ticks = utime + stime;
    Some(Duration::from_millis(ticks * 1000 / USER_HZ))
}

/// CPU use in percent of one core over `wall`.
pub fn percent(cpu: Duration, wall: Duration) -> f64 {
    if wall.is_zero() {
        return 0.0;
    }
    cpu.as_secs_f64() / wall.as_secs_f64() * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utime_and_stime_after_a_name_with_spaces() {
        let stat = "42 (a b) c) S 1 2 3 4 5 6 7 8 9 10 150 50 0 0 20 0 1 0";
        assert_eq!(stat_time(stat), Some(Duration::from_secs(2)));
        assert_eq!(stat_time("42 (x) S 1"), None);
        assert_eq!(stat_time("garbage"), None);
    }

    #[test]
    fn reads_own_time_and_rejects_missing_pids() {
        assert!(own_time().is_some());
        assert!(process_time(u32::MAX).is_none());
    }

    #[test]
    fn computes_percent_of_one_core() {
        let p = percent(Duration::from_millis(500), Duration::from_secs(1));
        assert!((p - 50.0).abs() < 1e-9);
        assert!(percent(Duration::from_secs(1), Duration::ZERO).abs() < f64::EPSILON);
    }
}
