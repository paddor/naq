//! A log file, renamed past a size and purged to a count of files, as
//! `nats-server` keeps it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{Format, Level, Parts};
use crate::Logging;

#[derive(Debug)]
pub(super) struct File {
    path: PathBuf,
    f: std::fs::File,
    /// Bytes in it, as far as this log knows.
    size: u64,
    /// Past this many bytes it is rotated; 0 never.
    limit: u64,
    /// Files kept, the current one counted; 0 all.
    max_files: usize,
    /// A line to log once it is open.
    note: Option<String>,
}

impl File {
    pub(super) fn open(path: &Path, l: &Logging) -> std::io::Result<File> {
        let f = open(path)?;
        let size = f.metadata()?.len();
        let note = (l.size_limit > 0 && size > l.size_limit).then(|| "Rotating logfile...".into());
        Ok(File {
            path: path.to_path_buf(),
            f,
            size,
            limit: l.size_limit,
            max_files: l.max_files,
            note,
        })
    }

    pub(super) const fn take_note(&mut self) -> Option<String> {
        self.note.take()
    }

    /// Appends `line`, then rotates the file if it grew past its limit.
    pub(super) fn write(&mut self, format: Format, line: &str) {
        if self.f.write_all(line.as_bytes()).is_err() {
            return;
        }
        self.size += line.len() as u64;
        if self.limit > 0 && self.size > self.limit {
            self.rotate(format);
        }
    }

    /// Opens the file at its path again, as after it was moved away.
    pub(super) fn reopen(&mut self) -> std::io::Result<()> {
        let f = open(&self.path)?;
        self.size = f.metadata()?.len();
        self.f = f;
        Ok(())
    }

    /// Renames the file to its path and the time, starts a new one, and
    /// removes the oldest backups past the count.
    fn rotate(&mut self, format: Format) {
        let t = Parts::of(SystemTime::now());
        let backup = format!(
            "{}.{:04}.{:02}.{:02}.{:02}.{:02}.{:02}.{:09}",
            self.path.display(),
            t.year,
            t.month,
            t.day,
            t.hour,
            t.min,
            t.sec,
            t.nanos
        );
        let _ = std::fs::rename(&self.path, &backup);
        // If it cannot be opened, lines go on into the backup.
        let Ok(f) = open(&self.path) else {
            return;
        };
        self.f = f;
        let note = format!("Rotated log, backup saved as {backup:?}");
        self.size = self.direct(format, Level::Info, &note);
        if self.max_files > 0 {
            self.purge(format);
        }
    }

    /// Removes the oldest backups until `max_files - 1` are left.
    fn purge(&mut self, format: Format) {
        let dir = match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let Some(base) = self.path.file_name().and_then(|b| b.to_str()) else {
            return;
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                let text = format!(
                    "Unable to read directory {:?} for log purge ({e}), will attempt next rotation",
                    dir.display().to_string()
                );
                self.direct(format, Level::Error, &text);
                return;
            }
        };
        let prefix = format!("{base}.");
        let mut backups: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| !t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.strip_prefix(&prefix).is_some_and(stamp))
            .collect();
        backups.sort();
        let excess = backups.len().saturating_sub(self.max_files - 1);
        for name in &backups[..excess] {
            if let Err(e) = std::fs::remove_file(dir.join(name)) {
                let text = format!(
                    "Unable to remove backup log file {name:?} ({e}), will attempt next rotation"
                );
                self.direct(format, Level::Error, &text);
                return;
            }
            self.direct(format, Level::Info, &format!("Purged log file {name:?}"));
        }
    }

    /// Writes a line of the log's own, ended as `nats-server` ends them:
    /// with `\r\n`. Returns its length.
    fn direct(&mut self, format: Format, level: Level, text: &str) -> u64 {
        let line = format.line(level, format_args!("{text}"), "\r\n");
        let _ = self.f.write_all(line.as_bytes());
        line.len() as u64
    }
}

fn open(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
    o.open(path)
}

/// Whether `s` is the time a backup's name ends in:
/// `YYYY.MM.DD.hh.mm.ss` and up to nine digits of a second.
fn stamp(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    let digits = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_digit());
    let in_range =
        |p: &str, lo: u32, hi: u32| p.parse::<u32>().is_ok_and(|v| (lo..=hi).contains(&v));
    let fraction = match parts.len() {
        6 => true,
        7 => (1..=9).contains(&parts[6].len()) && parts[6].bytes().all(|b| b.is_ascii_digit()),
        _ => false,
    };
    fraction
        && digits(parts[0], 4)
        && parts[1..6].iter().all(|p| digits(p, 2))
        && in_range(parts[1], 1, 12)
        && in_range(parts[2], 1, 31)
        && in_range(parts[3], 0, 23)
        && in_range(parts[4], 0, 59)
        && in_range(parts[5], 0, 59)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> Format {
        Format {
            pid: 1,
            time: false,
            color: false,
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("naq-log-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn files(d: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn backup_names_end_in_the_time() {
        assert!(stamp("2026.11.06.02.18.09.898248068"));
        assert!(stamp("2026.11.06.02.18.09"));
        for bad in [
            "2026.13.06.02.18.09.1",
            "2026.11.06.02.18",
            "26.11.06.02.18.09.1",
            "2026.11.06.02.18.09.1234567890",
            "2026.11.06.02.18.09.x",
        ] {
            assert!(!stamp(bad), "{bad}");
        }
    }

    #[test]
    fn a_file_past_its_limit_is_rotated_and_purged_to_its_count() {
        let d = dir("rotate");
        let path = d.join("s.log");
        let l = Logging {
            size_limit: 100,
            max_files: 2,
            ..Logging::default()
        };
        let mut f = File::open(&path, &l).unwrap();
        let line = "x".repeat(60) + "\n";
        for _ in 0..6 {
            f.write(format(), &line);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let names = files(&d);
        assert_eq!(names.len(), 2, "{names:?}");
        assert_eq!(names[0], "s.log");
        assert!(names[1].starts_with("s.log.2"), "{names:?}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("[1] [INF] Rotated log, backup saved as \""),
            "{text}"
        );
        assert!(
            text.contains("[1] [INF] Purged log file \"s.log."),
            "{text}"
        );
        assert!(text.split('\n').next().unwrap().ends_with('\r'));
    }

    #[test]
    fn a_file_over_its_limit_at_open_says_it_rotates() {
        let d = dir("over");
        let path = d.join("s.log");
        std::fs::write(&path, "y".repeat(200)).unwrap();
        let l = Logging {
            size_limit: 100,
            ..Logging::default()
        };
        let mut f = File::open(&path, &l).unwrap();
        assert_eq!(f.take_note().as_deref(), Some("Rotating logfile..."));
        assert_eq!(f.take_note(), None);
    }

    #[test]
    fn a_reopened_file_takes_lines_at_its_path_again() {
        let d = dir("reopen");
        let path = d.join("s.log");
        let mut f = File::open(&path, &Logging::default()).unwrap();
        f.write(format(), "a\n");
        std::fs::rename(&path, d.join("old.log")).unwrap();
        f.reopen().unwrap();
        f.write(format(), "b\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b\n");
        assert_eq!(std::fs::read_to_string(d.join("old.log")).unwrap(), "a\n");
    }
}
