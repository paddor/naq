//! Times and durations as `nats-server` writes them: Go's formats.

use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `t` as RFC 3339 in UTC, with all nine digits of nanoseconds.
pub(crate) fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, day) = civil(days.cast_signed());
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        d.subsec_nanos()
    )
}

/// `t` in RFC 3339 with nanoseconds, UTC, trailing zeros cut, as Go
/// writes a time in JSON.
pub(crate) fn rfc3339_nano(t: SystemTime) -> String {
    let full = rfc3339(t);
    let (whole, fraction) = full
        .trim_end_matches('Z')
        .split_once('.')
        .unwrap_or((&full, ""));
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{whole}Z")
    } else {
        format!("{whole}.{fraction}Z")
    }
}

/// `t` as HTTP writes dates: `Tue, 03 Nov 2026 20:47:19 GMT`.
pub(crate) fn http_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil(days.cast_signed());
    format!(
        "{}, {d:02} {} {y} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[m as usize - 1],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Year, month and day of `days` since 1970-01-01.
pub(crate) const fn civil(days: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days-to-civil.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// Days since 1970-01-01 of `year`, `month` and `day`.
pub(crate) const fn days(year: i64, month: i64, day: i64) -> i64 {
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `up` as `nats-server` writes uptimes, in whole seconds: `1y2d3h4m5s`,
/// from the largest unit that is not zero.
pub(crate) fn uptime(up: Duration) -> String {
    let secs = up.as_secs();
    let (years, days) = (secs / 31_536_000, secs / 86_400 % 365);
    let (hours, mins, sec) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    for (n, unit) in [(years, 'y'), (days, 'd'), (hours, 'h'), (mins, 'm')] {
        if n > 0 || !out.is_empty() {
            let _ = write!(out, "{n}{unit}");
        }
    }
    let _ = write!(out, "{sec}s");
    out
}

/// Round trip `d` as `nats-server` reports it: to the microsecond between
/// one and a thousand of them, else as it is.
pub(crate) fn go_rtt(d: Duration) -> Duration {
    let micros = Duration::from_micros(1)..Duration::from_millis(1);
    if micros.contains(&d) && d != micros.start {
        // Below a millisecond: fits.
        Duration::from_micros(d.as_micros() as u64)
    } else {
        d
    }
}

/// `d` as Go's `Duration.String` writes it: `0s`, `850ns`, `1.5us` with
/// a micro sign for the `u`, `14.083277ms`, `2m3.5s`, `1h0m0s`.
pub(crate) fn go_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return fraction(ns, 1_000, "\u{b5}s");
    }
    if ns < 1_000_000_000 {
        return fraction(ns, 1_000_000, "ms");
    }
    let secs = d.as_secs();
    let (h, m) = (secs / 3600, secs / 60 % 60);
    let s = fraction(
        u128::from(secs % 60) * 1_000_000_000 + u128::from(d.subsec_nanos()),
        1_000_000_000,
        "s",
    );
    match (h, m) {
        (0, 0) => s,
        (0, _) => format!("{m}m{s}"),
        _ => format!("{h}h{m}m{s}"),
    }
}

/// `n` in units of `per`, with as many decimals as it needs, and `unit`.
fn fraction(n: u128, per: u128, unit: &str) -> String {
    let (whole, part) = (n / per, n % per);
    if part == 0 {
        return format!("{whole}{unit}");
    }
    let digits = per.ilog10() as usize;
    let part = format!("{part:0digits$}");
    format!("{whole}.{}{unit}", part.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_below_a_millisecond_drop_their_nanoseconds() {
        let ns = Duration::from_nanos;
        assert_eq!(go_rtt(ns(547_774)), ns(547_000));
        assert_eq!(go_rtt(ns(1_271_087)), ns(1_271_087));
        assert_eq!(go_rtt(ns(1_000)), ns(1_000));
        assert_eq!(go_rtt(ns(999)), ns(999));
    }

    #[test]
    fn times_are_written_as_go_writes_them() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        assert_eq!(rfc3339(t), "2023-11-14T22:13:20.000000005Z");
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000000000Z");
        let trimmed = UNIX_EPOCH + Duration::new(1_700_000_000, 120_000_000);
        assert_eq!(rfc3339_nano(trimmed), "2023-11-14T22:13:20.12Z");
        assert_eq!(rfc3339_nano(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(http_date(t), "Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
        for d in [-1, 0, 59, 11_016, 20_000, 2_000_000] {
            let (y, m, day) = civil(d);
            assert_eq!(days(y, m.into(), day.into()), d);
        }
    }

    #[test]
    fn uptimes_count_from_the_largest_unit() {
        let up = |s| uptime(Duration::from_secs(s));
        assert_eq!(up(0), "0s");
        assert_eq!(up(42), "42s");
        assert_eq!(up(123), "2m3s");
        assert_eq!(up(3605), "1h0m5s");
        assert_eq!(up(3 * 86_400 + 1), "3d0h0m1s");
        assert_eq!(
            up(31_536_000 + 2 * 86_400 + 3 * 3600 + 4 * 60 + 5),
            "1y2d3h4m5s"
        );
        assert_eq!(uptime(Duration::from_millis(1999)), "1s");
    }

    #[test]
    fn durations_are_written_as_go_writes_them() {
        let d = |ns| go_duration(Duration::from_nanos(ns));
        assert_eq!(d(0), "0s");
        assert_eq!(d(850), "850ns");
        assert_eq!(d(433_000), "433\u{b5}s");
        assert_eq!(d(1_500), "1.5\u{b5}s");
        assert_eq!(d(1_271_087), "1.271087ms");
        assert_eq!(d(2_000_000_000), "2s");
        assert_eq!(d(2_500_000_001), "2.500000001s");
        assert_eq!(d(123_500_000_000), "2m3.5s");
        assert_eq!(d(3_600_000_000_000), "1h0m0s");
        assert_eq!(d(3_660_000_000_000), "1h1m0s");
    }
}
