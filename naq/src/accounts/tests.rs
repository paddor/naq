use super::*;

fn prefix() -> Responses {
    Responses::new(|n| n / 2)
}

#[test]
fn accounts_keep_their_ids_by_name() {
    let names = ["$G".to_owned(), "A".to_owned()];
    let a = Accounts::new(&names, [Imports::default()], false, prefix);
    assert_eq!(a.len(), 2);
    assert_eq!((a.id("$G"), a.id("A"), a.id("B")), (Some(0), Some(1), None));
    assert_eq!(a.id_of(b"A"), Some(1));
    assert_eq!(a.id_of(&[0xff]), None, "not UTF-8");
    assert_eq!((a.name(1), a.name(9)), ("A", "$G"));
    assert!(a.lds(1).starts_with(b"$LDS."));
    assert_eq!(a.lds(9), b"");
    let all: Vec<(u32, &str)> = a.iter().map(|(id, x)| (id, x.name.as_str())).collect();
    assert_eq!(all, [(0, "$G"), (1, "A")]);
}

#[test]
fn accounts_are_added_in_chunks_up_to_the_most() {
    let fixed = Accounts::of(&["$G"]);
    assert_eq!(fixed.room(), chunks(MOST));
    assert!(!fixed.growing());
    let growing = Accounts::new(&["$G".to_owned()], [], true, prefix);
    assert!(growing.growing());
    for n in 1..=CHUNK {
        growing.add(&format!("A{n}"), prefix);
    }
    assert_eq!(growing.id("A256"), Some(256), "in a second chunk");
    assert_eq!(growing.add("A1", prefix), Some(1), "added once");
    assert_eq!(growing.len(), 257);
}

#[test]
fn imports_are_set_once() {
    let a = Accounts::of(&["$G"]);
    assert_eq!(a.imports(0), &Imports::default());
    assert_eq!(a.imports(7), &Imports::default(), "no such account");
    let account = a.get(0).unwrap();
    assert!(account.set_imports(Imports::default()));
    assert!(!account.set_imports(Imports::default()));
}
