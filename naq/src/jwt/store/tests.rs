use std::sync::atomic::{AtomicU32, Ordering};

use nkeys::KeyPair;
use serde_json::json;

use super::*;
use crate::jwt::tests::mint_with;

/// A fresh directory, removed when it drops.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        // Relaxed: only uniqueness matters.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("naq-store-{}-{n}", std::process::id()));
        Dir(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An account JWT of `kp`, by the operator `op`, issued at `iat`, as
/// `jti`, expiring at `exp` if not 0.
fn account(op: &KeyPair, kp: &KeyPair, iat: i64, jti: &str, exp: i64) -> String {
    let header = json!({"typ": "JWT", "alg": "ed25519-nkey"});
    let mut payload = json!({
        "jti": jti, "iat": iat, "iss": op.public_key(), "sub": kp.public_key(),
        "nats": {"type": "account", "version": 2},
    });
    if exp > 0 {
        payload["exp"] = exp.into();
    }
    mint_with(op, &header, &payload)
}

fn full(dir: &Dir, delete: Delete) -> Store {
    Store::open(&dir.0, delete, usize::MAX, false, None).unwrap()
}

#[test]
fn a_store_keeps_one_file_per_account_and_a_hash_of_all() {
    let (dir, op) = (Dir::new(), KeyPair::new_operator());
    let (a, b) = (KeyPair::new_account(), KeyPair::new_account());
    let s = full(&dir, Delete::No);
    assert_eq!(s.hash(), [0; 32]);
    let (ja, jb) = (account(&op, &a, 1, "A1", 0), account(&op, &b, 1, "B1", 0));
    assert_eq!(s.save(&a.public_key(), &ja), Ok(true));
    assert_eq!(s.save(&a.public_key(), &ja), Ok(false), "the same again");
    assert_eq!(s.save(&b.public_key(), &jb), Ok(true));
    assert_eq!(s.load(&a.public_key()), Some(ja.clone()));
    assert_eq!(s.load(&KeyPair::new_account().public_key()), None);
    assert_eq!(s.save("nokey", &ja), Err("invalid public key".into()));
    assert_eq!(s.save(&a.public_key(), ""), Err("invalid JWT".into()));
    let mut both = sha(&ja);
    xor(&mut both, &sha(&jb));
    assert_eq!(s.hash(), both);
    let file = dir.0.join(format!("{}.jwt", a.public_key()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(full(&dir, Delete::No).hash(), both, "read again at open");
}

#[test]
fn only_newer_jwts_replace_others_unless_they_are_updates() {
    let (dir, op, a) = (Dir::new(), KeyPair::new_operator(), KeyPair::new_account());
    let key = a.public_key();
    let s = full(&dir, Delete::No);
    let (old, new) = (account(&op, &a, 5, "OLD", 0), account(&op, &a, 9, "NEW", 0));
    assert_eq!(s.save_if_newer(&key, &new), Ok(true));
    assert_eq!(s.save_if_newer(&key, &old), Ok(false), "older");
    assert_eq!(
        s.save_if_newer(&key, &account(&op, &a, 10, "NEW", 0)),
        Ok(false),
        "same jti"
    );
    let other = account(&op, &KeyPair::new_account(), 11, "X", 0);
    assert_eq!(
        s.save_if_newer(&key, &other),
        Err("jwt subject nkey and provided nkey do not match".into())
    );
    assert!(s.save_if_newer(&key, "junk").is_err());
    assert_eq!(s.save(&key, &old), Ok(true), "an update may be older");
    assert_eq!(s.load(&key), Some(old));
}

#[test]
fn a_full_store_refuses_more_and_a_cache_drops_the_least_used() {
    let (dir, op) = (Dir::new(), KeyPair::new_operator());
    let keys: Vec<KeyPair> = (0..3).map(|_| KeyPair::new_account()).collect();
    let jwt = |i: usize| account(&op, &keys[i], 1, "J", 0);
    let key = |i: usize| keys[i].public_key();
    let s = Store::open(&dir.0, Delete::No, 1, false, None).unwrap();
    s.save(&key(0), &jwt(0)).unwrap();
    assert_eq!(s.save(&key(1), &jwt(1)), Err("jwt store is full".into()));
    let cache_dir = Dir::new();
    let c = Store::open(&cache_dir.0, Delete::Remove, 2, true, None).unwrap();
    c.save(&key(0), &jwt(0)).unwrap();
    c.save(&key(1), &jwt(1)).unwrap();
    assert!(c.load(&key(0)).is_some(), "used last");
    assert_eq!(c.save(&key(2), &jwt(2)), Ok(true));
    assert_eq!(c.load(&key(1)), None, "the least used went");
    assert!(c.load(&key(0)).is_some());
}

#[test]
fn deletes_rename_or_remove_as_the_store_is_set_up() {
    let (op, a) = (KeyPair::new_operator(), KeyPair::new_account());
    let key = a.public_key();
    let jwt = account(&op, &a, 1, "J", 0);
    let dir = Dir::new();
    let no = full(&dir, Delete::No);
    no.save(&key, &jwt).unwrap();
    assert_eq!(
        no.delete(&key),
        Err("store is not set up to for delete".into())
    );
    let renamed = full(&dir, Delete::Rename);
    assert_eq!(renamed.delete(&key), Ok(true));
    assert_eq!(renamed.hash(), [0; 32]);
    assert!(dir.0.join(format!("{key}.jwt.deleted")).exists());
    assert_eq!(renamed.delete(&key), Ok(false), "gone already");
    let removed = full(&dir, Delete::Remove);
    removed.save(&key, &jwt).unwrap();
    assert_eq!(removed.delete(&key), Ok(true));
    assert_eq!(removed.load(&key), None);
}

#[test]
fn packs_carry_the_jwts_not_expired_to_another_store() {
    let op = KeyPair::new_operator();
    let (a, b) = (KeyPair::new_account(), KeyPair::new_account());
    let (one, two) = (Dir::new(), Dir::new());
    let s = full(&one, Delete::No);
    s.save(&a.public_key(), &account(&op, &a, 1, "A", 0))
        .unwrap();
    s.save(&b.public_key(), &account(&op, &b, 1, "B", 1))
        .unwrap();
    let pack = s.pack();
    assert_eq!(pack.len(), 1, "the expired one stays out");
    let t = full(&two, Delete::No);
    assert_eq!(t.merge(&pack.join("\n")), Ok(vec![a.public_key()]));
    assert_eq!(t.merge(&pack.join("\n")), Ok(Vec::new()), "nothing newer");
    assert!(t.merge("x|y|z").is_err());
    assert_eq!(
        t.merge("AX|y"),
        Err("key to merge is not a valid public account key".into())
    );
}

#[test]
fn jwts_go_once_they_expire_or_their_ttl_passes() {
    let (op, a, b) = (
        KeyPair::new_operator(),
        KeyPair::new_account(),
        KeyPair::new_account(),
    );
    let dir = Dir::new();
    let s = full(&dir, Delete::No);
    let now = SystemTime::now();
    s.save(&a.public_key(), &account(&op, &a, 1, "A", 100))
        .unwrap();
    s.save(&b.public_key(), &account(&op, &b, 1, "B", 0))
        .unwrap();
    assert_eq!(s.expire(now), vec![a.public_key()]);
    assert_eq!(s.load(&a.public_key()), None);
    assert_eq!(s.sweep_every(), Duration::from_secs(60));
    let cache_dir = Dir::new();
    let ttl = Duration::from_secs(10);
    let c = Store::open(&cache_dir.0, Delete::Remove, 10, true, Some(ttl)).unwrap();
    c.save(&b.public_key(), &account(&op, &b, 1, "B", 0))
        .unwrap();
    assert_eq!(c.expire(now), Vec::<String>::new());
    assert_eq!(c.expire(now + 2 * ttl), vec![b.public_key()]);
    assert_eq!(c.sweep_every(), Duration::from_secs(5));
}
