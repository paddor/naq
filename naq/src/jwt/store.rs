//! The directory of a full or cache resolver, as `nats-server` keeps it:
//! one file `<account key>.jwt` each, tracked by a hash of all of them, by
//! use and by expiry.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rustc_hash::FxHashMap;
use sha2::{Digest, Sha256};

use super::{Claims, decode_generic};
use crate::Delete;

/// The file name ending of a JWT.
const EXT: &str = ".jwt";

/// The JWTs of a directory resolver.
#[derive(Debug)]
pub(crate) struct Store {
    dir: PathBuf,
    delete: Delete,
    /// The most JWTs kept.
    limit: usize,
    /// At the limit, the least used JWT goes: a cache. Else a JWT more is
    /// refused.
    evict: bool,
    /// How long a JWT stays after its last use, if it does not stay until
    /// it expires.
    ttl: Option<Duration>,
    tracked: Mutex<Tracked>,
}

/// What the store knows of its files.
#[derive(Debug, Default)]
struct Tracked {
    by_key: FxHashMap<String, File>,
    /// The XOR of the hashes of all files.
    hash: [u8; 32],
    /// Counts uses, to order them.
    clock: u64,
}

/// One file.
#[derive(Debug, Clone, Copy)]
struct File {
    /// The SHA-256 of what it holds.
    hash: [u8; 32],
    /// When it goes, if it does.
    expires: Option<SystemTime>,
    /// When it was last used, by the store's clock.
    used: u64,
}

/// Why a store would not take or give a JWT.
pub(crate) type Refusal = String;

impl Tracked {
    /// Tracks file `key` of `hash`, expiring at `expires`.
    fn track(&mut self, key: &str, hash: [u8; 32], expires: Option<SystemTime>) {
        self.clock += 1;
        let file = File {
            hash,
            expires,
            used: self.clock,
        };
        if let Some(old) = self.by_key.insert(key.to_owned(), file) {
            xor(&mut self.hash, &old.hash);
        }
        xor(&mut self.hash, &hash);
    }

    /// Notes a use of file `key`, which then stays `ttl` more, if given.
    fn touch(&mut self, key: &str, ttl: Option<Duration>) {
        self.clock += 1;
        let clock = self.clock;
        if let Some(f) = self.by_key.get_mut(key) {
            f.used = clock;
            if let Some(ttl) = ttl {
                f.expires = SystemTime::now().checked_add(ttl);
            }
        }
    }

    /// Stops tracking file `key`.
    fn untrack(&mut self, key: &str) {
        if let Some(old) = self.by_key.remove(key) {
            xor(&mut self.hash, &old.hash);
        }
    }

    /// The key of the least used file.
    fn least_used(&self) -> Option<String> {
        self.by_key
            .iter()
            .min_by_key(|(_, f)| f.used)
            .map(|(k, _)| k.clone())
    }
}

fn xor(into: &mut [u8; 32], other: &[u8; 32]) {
    for (a, b) in into.iter_mut().zip(other) {
        *a ^= b;
    }
}

/// Claims with no body: only what the store reads.
type Generic = Claims<serde::de::IgnoredAny>;

impl Store {
    /// The store in `dir`, made if missing, of the files there; one that
    /// `evict`s at `limit`, or refuses more, and keeps JWTs `ttl` after
    /// their last use, if given.
    ///
    /// # Errors
    ///
    /// If `dir` cannot be made or read.
    pub(crate) fn open(
        dir: &Path,
        delete: Delete,
        limit: usize,
        evict: bool,
        ttl: Option<Duration>,
    ) -> io::Result<Store> {
        make_dir(dir)?;
        let mut store = Store {
            dir: dir.to_owned(),
            delete,
            limit,
            evict,
            ttl,
            tracked: Mutex::default(),
        };
        let mut tracked = Tracked::default();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(key) = key_of(&path) else {
                continue;
            };
            if let Ok(jwt) = std::fs::read_to_string(&path) {
                tracked.track(key, sha(&jwt), store.expiry(&jwt));
            }
        }
        store.tracked = Mutex::new(tracked);
        Ok(store)
    }

    /// When a JWT `jwt` stored now goes: `ttl` from now, else when it
    /// expires.
    fn expiry(&self, jwt: &str) -> Option<SystemTime> {
        if let Some(ttl) = self.ttl {
            return SystemTime::now().checked_add(ttl);
        }
        let exp = decode_generic::<serde::de::IgnoredAny>(jwt).ok()?.exp;
        (exp > 0).then(|| std::time::UNIX_EPOCH + Duration::from_secs(exp.cast_unsigned()))
    }

    /// The file of account `key`, if it is an account key.
    fn path(&self, key: &str) -> Option<PathBuf> {
        super::is_key(key, 'A').then(|| self.dir.join(format!("{key}{EXT}")))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tracked> {
        self.tracked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The JWT of account `key`, if the store has it: a use.
    pub(crate) fn load(&self, key: &str) -> Option<String> {
        let path = self.path(key)?;
        let mut t = self.lock();
        let jwt = std::fs::read_to_string(path).ok()?;
        t.touch(key, self.ttl);
        Some(jwt)
    }

    /// Stores `jwt` for account `key`, even if older than the one there,
    /// as an update is: whether it changed the store.
    ///
    /// # Errors
    ///
    /// If the key is no account key, the store is full, or the file
    /// cannot be written.
    pub(crate) fn save(&self, key: &str, jwt: &str) -> Result<bool, Refusal> {
        let path = self.path(key).ok_or("invalid public key")?;
        let mut t = self.lock();
        self.write(&mut t, key, &path, jwt)
    }

    /// Stores `jwt` for account `key` unless the one there is the same or
    /// newer: whether it changed the store.
    ///
    /// # Errors
    ///
    /// As [`Store::save`], and if `jwt` is not a JWT of that account.
    pub(crate) fn save_if_newer(&self, key: &str, jwt: &str) -> Result<bool, Refusal> {
        let path = self.path(key).ok_or("invalid public key")?;
        let mut t = self.lock();
        if let Ok(there) = std::fs::read_to_string(&path) {
            let new: Generic = decode_generic(jwt).map_err(|e| e.to_string())?;
            if let Ok(old) = decode_generic::<serde::de::IgnoredAny>(&there) {
                if old.jti == new.jti || old.iat > new.iat {
                    return Ok(false);
                }
                if new.sub != key {
                    return Err("jwt subject nkey and provided nkey do not match".into());
                }
                if old.sub != new.sub {
                    return Err("subject of existing and new jwt do not match".into());
                }
            }
        }
        self.write(&mut t, key, &path, jwt)
    }

    /// Writes `jwt` to `path`, the file of `key`, unless it holds it
    /// already: whether it did.
    fn write(&self, t: &mut Tracked, key: &str, path: &Path, jwt: &str) -> Result<bool, Refusal> {
        if jwt.is_empty() {
            return Err("invalid JWT".into());
        }
        let hash = sha(jwt);
        match t.by_key.get(key).map(|f| f.hash == hash) {
            Some(true) => {
                t.touch(key, None);
                return Ok(false);
            }
            Some(false) => {}
            None if t.by_key.len() < self.limit => {}
            None if !self.evict => return Err("jwt store is full".into()),
            None => {
                if let Some(old) = t.least_used() {
                    let gone = self.path(&old).map(std::fs::remove_file);
                    if let Some(Err(e)) = gone {
                        return Err(e.to_string());
                    }
                    t.untrack(&old);
                }
            }
        }
        write_file(path, jwt).map_err(|e| e.to_string())?;
        t.track(key, hash, self.expiry(jwt));
        Ok(true)
    }

    /// Deletes the JWT of account `key`, renamed or removed as the store
    /// deletes: whether it was there.
    ///
    /// # Errors
    ///
    /// If the store does not delete, or the file cannot be.
    pub(crate) fn delete(&self, key: &str) -> Result<bool, Refusal> {
        let path = self.path(key).ok_or("invalid public key")?;
        let mut t = self.lock();
        let done = match self.delete {
            Delete::No => return Err("store is not set up to for delete".into()),
            Delete::Rename => {
                let mut to = path.clone().into_os_string();
                to.push(".deleted");
                std::fs::rename(&path, to)
            }
            Delete::Remove => std::fs::remove_file(&path),
        };
        match done {
            Ok(()) => {
                t.untrack(key);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Whether it deletes JWTs when asked.
    pub(crate) fn deletes(&self) -> bool {
        self.delete != Delete::No
    }

    /// The XOR of the SHA-256 of every JWT.
    pub(crate) fn hash(&self) -> [u8; 32] {
        self.lock().hash
    }

    /// Every JWT tracked and not expired, as `<key>|<jwt>`, in no order.
    pub(crate) fn pack(&self) -> Vec<String> {
        let t = self.lock();
        let now = super::now();
        t.by_key
            .keys()
            .filter_map(|key| {
                let jwt = std::fs::read_to_string(self.path(key)?).ok()?;
                let exp = decode_generic::<serde::de::IgnoredAny>(&jwt).map_or(0, |c| c.exp);
                (!jwt.is_empty() && (exp == 0 || exp >= now)).then(|| format!("{key}|{jwt}"))
            })
            .collect()
    }

    /// Takes the JWTs of `pack`, lines of `<key>|<jwt>`, where newer: the
    /// keys it changed.
    ///
    /// # Errors
    ///
    /// At the first line that does not hold; those before it are taken.
    pub(crate) fn merge(&self, pack: &str) -> Result<Vec<String>, Refusal> {
        let mut changed = Vec::new();
        for line in pack.split('\n').filter(|l| !l.is_empty()) {
            let parts: Vec<&str> = line.split('|').collect();
            let [key, jwt] = parts[..] else {
                return Err(format!(
                    "line in package didn't contain 2 entries: {line:?}"
                ));
            };
            if !super::is_key(key, 'A') {
                return Err("key to merge is not a valid public account key".into());
            }
            if self.save_if_newer(key, jwt)? {
                changed.push(key.to_owned());
            }
        }
        Ok(changed)
    }

    /// Removes the files expired at `now`: their keys.
    pub(crate) fn expire(&self, now: SystemTime) -> Vec<String> {
        let mut t = self.lock();
        let gone: Vec<String> = t
            .by_key
            .iter()
            .filter(|(_, f)| f.expires.is_some_and(|e| e <= now))
            .map(|(k, _)| k.clone())
            .collect();
        gone.into_iter()
            .filter(|key| {
                let removed = self
                    .path(key)
                    .is_some_and(|p| std::fs::remove_file(p).is_ok());
                if removed {
                    t.untrack(key);
                }
                removed
            })
            .collect()
    }

    /// How often expired files are looked for: every minute, or half the
    /// `ttl` if less.
    pub(crate) fn sweep_every(&self) -> Duration {
        let minute = Duration::from_secs(60);
        self.ttl
            .map_or(minute, |t| (t / 2).clamp(Duration::from_millis(1), minute))
    }
}

/// The account key a file `path` holds the JWT of, if it is one.
fn key_of(path: &Path) -> Option<&str> {
    path.file_name()?.to_str()?.strip_suffix(EXT)
}

fn sha(jwt: &str) -> [u8; 32] {
    Sha256::digest(jwt.as_bytes()).into()
}

/// Makes `dir`, if missing, as `nats-server` does: for its owner only.
fn make_dir(dir: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Writes `jwt` to `path`, readable by its owner only.
fn write_file(path: &Path, jwt: &str) -> io::Result<()> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?.write_all(jwt.as_bytes())
}

#[cfg(test)]
mod tests;
