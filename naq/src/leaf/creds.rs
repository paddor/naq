//! What a link proves its identity to the hub with: the hub's nonce,
//! signed with a user NKey seed, alone or from a credentials file with the
//! user JWT.

use data_encoding::BASE64URL_NOPAD;
use nkeys::KeyPair;

use crate::Remote;

/// The keys of a `CONNECT` that prove the leaf's identity.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Proof {
    /// The user JWT of a credentials file.
    pub(super) jwt: Option<String>,
    /// The public key of a seed given alone.
    pub(super) nkey: Option<String>,
    /// The nonce signed, in URL-safe base64.
    pub(super) sig: Option<String>,
}

/// Signs `nonce` as remote `r` says: with the seed of its credentials
/// file, else with its seed. Without either, no proof.
///
/// # Errors
///
/// A credentials file that cannot be read or holds no JWT and seed, or a
/// seed that is not one.
pub(super) fn prove(r: &Remote, nonce: &str) -> Result<Proof, String> {
    if let Some(path) = &r.credentials {
        // A small file, read at each dial as `nats-server` does.
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("credentials {}: {e}", path.display()))?;
        let [jwt, seed] =
            items(&text).ok_or_else(|| format!("credentials {}: malformed", path.display()))?;
        return Ok(Proof {
            jwt: Some(jwt.to_owned()),
            nkey: None,
            sig: Some(sign(seed, nonce)?.1),
        });
    }
    let Some(seed) = &r.nkey else {
        return Ok(Proof::default());
    };
    let (key, sig) = sign(seed, nonce)?;
    Ok(Proof {
        jwt: None,
        nkey: Some(key),
        sig: Some(sig),
    })
}

/// Whether `seed` is the seed of a user NKey.
pub(super) fn is_user_seed(seed: &str) -> bool {
    KeyPair::from_seed(seed).is_ok_and(|k| k.public_key().starts_with('U'))
}

/// The public key of `seed`, and `nonce` signed with it.
fn sign(seed: &str, nonce: &str) -> Result<(String, String), String> {
    let key = KeyPair::from_seed(seed).map_err(|_| "malformed seed".to_owned())?;
    let sig = key
        .sign(nonce.as_bytes())
        .map_err(|_| "cannot sign".to_owned())?;
    Ok((key.public_key(), BASE64URL_NOPAD.encode(&sig)))
}

/// The first two items of a credentials file, the user JWT and the seed:
/// each a line of its own between lines that start and end with dashes,
/// as `nats-server` reads them.
fn items(text: &str) -> Option<[&str; 2]> {
    let dashes = |l: &str| l.len() >= 6 && l.starts_with("---") && l.ends_with("---");
    let item = |l: &str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.=".contains(&b))
    };
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut found = Vec::with_capacity(2);
    let mut i = 0;
    while i + 2 < lines.len() && found.len() < 2 {
        if dashes(lines[i]) && item(lines[i + 1]) && dashes(lines[i + 2]) {
            found.push(lines[i + 1]);
            i += 3;
        } else {
            i += 1;
        }
    }
    found.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "SUABXPISJ672XCVCU7XD7CVTTXYTBXTGZ4LX3WZCSLCPKHDPCXCLZVMVPI";

    fn creds(jwt: &str, seed: &str) -> String {
        format!(
            "-----BEGIN NATS USER JWT-----\n{jwt}\n------END NATS USER JWT------\n\n\
             ************************* IMPORTANT *************************\n\
             NKEY Seed printed below can be used to sign and prove identity.\n\n\
             -----BEGIN USER NKEY SEED-----\r\n{seed}\r\n------END USER NKEY SEED------\n\n\
             *************************************************************\n"
        )
    }

    fn verifies(key: &str, sig: &str, nonce: &str) -> bool {
        let sig = BASE64URL_NOPAD.decode(sig.as_bytes()).unwrap();
        KeyPair::from_public_key(key)
            .unwrap()
            .verify(nonce.as_bytes(), &sig)
            .is_ok()
    }

    #[test]
    fn a_credentials_file_gives_its_jwt_and_seed() {
        assert_eq!(
            items(&creds("eyJ.a-b_c.d=", SEED)),
            Some(["eyJ.a-b_c.d=", SEED])
        );
        assert_eq!(items("-----A-----\njwt\n-----B-----\n"), None, "no seed");
        assert_eq!(items(&creds("a b", SEED)), None, "not an item");
        assert_eq!(items(""), None);
    }

    #[test]
    fn the_nonce_is_signed_with_the_seed_of_the_file_or_the_seed() {
        let key = KeyPair::from_seed(SEED).unwrap().public_key();
        let dir = std::env::temp_dir().join(format!("naq-creds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user.creds");
        std::fs::write(&path, creds("the.jwt", SEED)).unwrap();
        let file = Remote {
            credentials: Some(path.clone()),
            nkey: Some("ignored".into()),
            ..Remote::default()
        };
        let p = prove(&file, "nonce").unwrap();
        assert_eq!((p.jwt.as_deref(), p.nkey), (Some("the.jwt"), None));
        assert!(verifies(&key, &p.sig.unwrap(), "nonce"));

        let seed = Remote {
            nkey: Some(SEED.into()),
            ..Remote::default()
        };
        let p = prove(&seed, "n2").unwrap();
        assert_eq!((p.jwt, p.nkey.as_deref()), (None, Some(key.as_str())));
        assert!(verifies(&key, &p.sig.unwrap(), "n2"));

        assert_eq!(prove(&Remote::default(), "n").unwrap(), Proof::default());
        std::fs::write(&path, "nothing").unwrap();
        assert!(prove(&file, "n").unwrap_err().ends_with("malformed"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(prove(&file, "n").is_err(), "gone");
        let bad = Remote {
            nkey: Some("SUnot".into()),
            ..Remote::default()
        };
        assert_eq!(prove(&bad, "n").unwrap_err(), "malformed seed");
    }

    #[test]
    fn only_user_seeds_are_seeds_of_remotes() {
        assert!(is_user_seed(SEED));
        let account = KeyPair::new_account().seed().unwrap();
        assert!(!is_user_seed(&account));
        assert!(!is_user_seed("SUnot"));
    }
}
