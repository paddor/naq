//! Updates of account JWTs over `$SYS`, as `nats-server` takes them with a
//! memory resolver: an account loaded takes the claims, and its clients
//! check themselves again.

use naq_proto::client::Pub;
use serde_json::json;

use crate::jwt::trust::live::Status;
use crate::lane::{Control, Lane, Outs};

/// The subjects updates come on.
pub(super) const UPDATES: [&[u8]; 2] = [
    b"$SYS.REQ.ACCOUNT.*.CLAIMS.UPDATE",
    b"$SYS.ACCOUNT.*.CLAIMS.UPDATE",
];

/// Takes the account JWT update `m`, which came on `lane`, answers it,
/// and tells every lane once an account took it.
pub(super) fn update(lane: &Lane, out: &mut Outs, m: &Pub<'_>) -> bool {
    let shared = &lane.shared;
    let Some(trust) = shared.trust() else {
        return false;
    };
    let Some(key) = account_of(m.subject) else {
        return false;
    };
    let status = trust.update(&key, &String::from_utf8_lossy(m.payload));
    if let Status::Updated(id) = status {
        shared.accounts.get(id).map(crate::accounts::Account::touch);
        for l in &shared.lanes {
            l.control(Control::Refresh { account: id });
        }
    }
    if let Some(reply) = m.reply.filter(|r| !r.is_empty()) {
        super::respond(lane, out, reply, &answer(&key, &status));
    }
    true
}

/// The account update subject `subject` names: token 3 of
/// `$SYS.REQ.ACCOUNT.<id>.CLAIMS.UPDATE`, or 2 of
/// `$SYS.ACCOUNT.<id>.CLAIMS.UPDATE`.
pub(super) fn account_of(subject: &[u8]) -> Option<String> {
    let tokens: Vec<&[u8]> = subject.split(|&b| b == b'.').collect();
    let id = match tokens.len() {
        6 => tokens[3],
        5 => tokens[2],
        _ => return None,
    };
    Some(String::from_utf8_lossy(id).into_owned())
}

/// The answer to an update of account `key` that went as `status`.
fn answer(key: &str, status: &Status) -> serde_json::Value {
    let data = |message: &str| json!({"data": {"account": key, "code": 200, "message": message}});
    match status {
        Status::Updated(_) | Status::Same => data("jwt updated"),
        Status::Skipped => data("jwt update skipped"),
        Status::Failed(message, why) => json!({"error": {
            "account": key,
            "code": 500,
            "description": format!("{message} - {why}"),
        }}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_names_its_account_by_either_subject() {
        assert_eq!(
            account_of(b"$SYS.REQ.ACCOUNT.AX.CLAIMS.UPDATE").as_deref(),
            Some("AX")
        );
        assert_eq!(
            account_of(b"$SYS.ACCOUNT.AX.CLAIMS.UPDATE").as_deref(),
            Some("AX")
        );
        assert_eq!(account_of(b"$SYS.REQ.CLAIMS.UPDATE"), None);
    }

    #[test]
    fn answers_say_how_an_update_went_as_nats_server_says_it() {
        let a = answer("AX", &Status::Updated(1));
        assert_eq!(a["data"]["message"], "jwt updated");
        assert_eq!(
            answer("AX", &Status::Skipped)["data"]["message"],
            "jwt update skipped"
        );
        let e = answer(
            "AX",
            &Status::Failed("jwt update error", "request body is empty".into()),
        );
        assert_eq!(e["error"]["code"], 500);
        assert_eq!(
            e["error"]["description"],
            "jwt update error - request body is empty"
        );
    }
}
