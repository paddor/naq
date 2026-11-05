use super::*;

#[test]
fn the_tighter_limit_holds_and_none_is_no_limit() {
    assert_eq!(tighter(NO_LIMIT, NO_LIMIT), NO_LIMIT);
    assert_eq!(tighter(NO_LIMIT, 5), 5);
    assert_eq!(tighter(3, NO_LIMIT), 3);
    assert_eq!(tighter(3, 5), 3);
    assert_eq!(tighter(0, 5), 0, "zero is no subscriptions at all");
}

#[test]
fn a_client_ip_is_in_a_cidr_or_not() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(in_cidr("127.0.0.0/8", ip("127.1.2.3")));
    assert!(!in_cidr("10.0.0.0/8", ip("127.1.2.3")));
    assert!(in_cidr("0.0.0.0/0", ip("8.8.8.8")));
    assert!(in_cidr("::1/128", ip("::1")) && !in_cidr("::1/128", ip("127.0.0.1")));
    assert!(!in_cidr("10.0.0.0", ip("10.0.0.0")) && !in_cidr("10.0.0.0/33", ip("10.0.0.0")));
    assert!(from_allowed(&[], None));
    assert!(!from_allowed(&["10.0.0.0/8".into()], None));
}

#[test]
fn a_time_window_holds_now_and_ends_on_time() {
    let day = |h: u64, m: u64| UNIX_EPOCH + Duration::from_secs(86_400 * 100 + h * 3600 + m * 60);
    let window_of = |start: &str, end: &str| claims::TimeRange {
        start: start.into(),
        end: end.into(),
    };
    assert_eq!(window(&[], "", day(1, 0)), Window::Always);
    let w = [window_of("01:00:00", "02:00:00")];
    assert_eq!(window(&w, "UTC", day(1, 30)), Window::Until(day(2, 0)));
    assert_eq!(window(&w, "", day(3, 0)), Window::Outside);
    // Past midnight: from 23:00 to 01:00 the next day.
    let night = [window_of("23:00:00", "01:00:00")];
    assert_eq!(window(&night, "", day(23, 30)), Window::Until(day(25, 0)));
    assert_eq!(window(&night, "", day(0, 30)), Window::Until(day(1, 0)));
    assert_eq!(
        window(&w, "Europe/Zurich", day(1, 30)),
        Window::Outside,
        "only UTC is served"
    );
    assert_eq!(clock("25:00:00"), None);
    assert_eq!(clock("01:02:03"), Some(3723));
}

#[test]
fn connection_types_drop_those_unknown() {
    let limits = |types: &[&str]| claims::UserLimits {
        allowed_connection_types: types.iter().map(|t| (*t).to_owned()).collect(),
        ..claims::UserLimits::default()
    };
    let tcp = ConnectionType::Standard;
    let ws = ConnectionType::Websocket;
    assert!(connects_as(&limits(&[]), tcp));
    assert!(connects_as(&limits(&["standard"]), tcp));
    assert!(!connects_as(&limits(&["WEBSOCKET"]), tcp) && connects_as(&limits(&["WEBSOCKET"]), ws));
    assert!(!connects_as(&limits(&["BOGUS"]), tcp));
}

#[test]
fn jwt_permissions_build_as_nats_server_builds_them() {
    assert!(defaults(&claims::Permissions::default()).is_none());
    let p = claims::Permissions {
        resp: Some(claims::ResponsePermission { max: 0, ttl: 0 }),
        ..claims::Permissions::default()
    };
    let perms = defaults(&p).unwrap();
    assert!(!perms.publish(b"x"), "with responses only, replies only");
}
