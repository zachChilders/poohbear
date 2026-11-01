//! Turning an untrusted request into a hardened `docker create` command.
//!
//! This is the security-critical function of the broker, so it is pure and
//! small. The policy fixes every flag; the request can only choose from a few
//! validated values (an allow-listed user, a terminal type and size, the
//! command to run). Attacker-controlled text only ever appears as a single
//! argument in a designated position, never inside a flag, and there is no
//! shell on the host to interpret it.

use hp_sandbox::proto::Request;

use crate::policy::{safe, Policy};

/// A planned sandbox: the arguments for `docker create`, and the name used to
/// start, find and remove it.
#[derive(Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: String,
    pub args: Vec<String>,
}

/// Why a request was refused. For the broker's log; the peer is told nothing.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejected(pub &'static str);

/// Longest command line accepted.
const MAX_COMMAND: usize = 16 * 1024;

/// Plan the sandbox for `req`. `name` is chosen by the broker, never by the peer.
pub fn plan(policy: &Policy, req: &Request, name: &str) -> Result<Spec, Rejected> {
    if let Some(command) = &req.command {
        if command.len() > MAX_COMMAND {
            return Err(Rejected("command too long"));
        }
        if command.contains('\0') {
            return Err(Rejected("command contains a NUL byte"));
        }
    }
    // Only accounts the operator listed; anything else gets the default.
    let user = if policy.users.contains(&req.user) {
        &req.user
    } else {
        &policy.default_user
    };
    let session = if safe(r"^[A-Za-z0-9-]{1,64}$", &req.session_id) {
        req.session_id.as_str()
    } else {
        "unknown"
    };
    let l = &policy.limits;

    let mut a: Vec<String> = Vec::new();
    let mut add = |items: &[&str]| a.extend(items.iter().map(|s| s.to_string()));
    add(&[
        "--rm",
        "-i",
        "--init",
        "--name",
        name,
        "--hostname",
        &policy.hostname,
    ]);
    add(&[
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
    ]);
    for dir in &policy.writable {
        add(&["--tmpfs", &format!("{dir}:rw,exec,nosuid,size={}", l.tmpfs)]);
    }
    add(&[
        "--pids-limit",
        &l.pids.to_string(),
        "--memory",
        &l.memory,
        "--memory-swap",
        &l.memory,
    ]);
    add(&[
        "--cpus",
        &l.cpus.to_string(),
        "--ulimit",
        "nofile=1024:1024",
    ]);
    add(&["--user", user, "--pull", "never", "--log-driver", "none"]);
    add(&[
        "--label",
        "honeypot.managed=true",
        "--label",
        &format!("honeypot.session={session}"),
    ]);
    if let Some(runtime) = &policy.runtime {
        add(&["--runtime", runtime]);
    }

    // What runs. A terminal is provided from inside the container by
    // `script`, so the broker needs no pty of its own. The numbers are
    // integers we format, and the shell path was validated with the policy.
    let shell = &policy.shell;
    let term = match &req.terminal {
        Some(t) if safe(r"^[A-Za-z0-9._-]{1,32}$", &t.term) => t.term.as_str(),
        _ => "xterm",
    };
    add(&["--env", &format!("TERM={term}"), "--env", "LANG=C.UTF-8"]);
    let tail: Vec<String> = match (&req.terminal, &req.command) {
        (Some(t), command) => {
            let (cols, rows) = (clamp(t.cols, 80), clamp(t.rows, 24));
            let run = match command {
                // the command travels in the environment, as one value
                Some(c) => {
                    add(&["--env", &format!("HP_COMMAND={c}")]);
                    // take it out of the environment before running it, so the
                    // command cannot see how it was delivered
                    format!("c=$HP_COMMAND; unset HP_COMMAND; exec {shell} -c \"$c\"")
                }
                None => format!("exec {shell} -l"),
            };
            vec![
                "script".into(),
                "-qec".into(),
                format!("stty rows {rows} cols {cols} 2>/dev/null; {run}"),
                "/dev/null".into(),
            ]
        }
        (None, Some(c)) => vec![shell.clone(), "-c".into(), c.clone()],
        (None, None) => vec![shell.clone(), "-l".into()],
    };
    a.push(policy.image.clone());
    a.extend(tail);
    Ok(Spec {
        name: name.to_string(),
        args: a,
    })
}

/// A terminal dimension: 0 means "unspecified", and nothing absurd gets through.
fn clamp(n: u16, default: u16) -> u16 {
    if n == 0 {
        default
    } else {
        n.min(500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TEST_POLICY;
    use hp_sandbox::proto::Terminal;

    fn policy() -> Policy {
        Policy::parse(TEST_POLICY).unwrap()
    }

    fn request() -> Request {
        Request {
            session_id: "abc-123".into(),
            user: "root".into(),
            command: None,
            terminal: None,
        }
    }

    fn terminal(cols: u16, rows: u16) -> Option<Terminal> {
        Some(Terminal {
            term: "xterm".into(),
            cols,
            rows,
        })
    }

    fn args(req: &Request) -> Vec<String> {
        plan(&policy(), req, "hp-test").unwrap().args
    }

    /// The value following `flag`.
    fn value<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn every_sandbox_gets_the_full_set_of_restrictions() {
        let a = args(&request());
        assert_eq!(value(&a, "--network"), ["none"], "no network, ever");
        assert_eq!(value(&a, "--cap-drop"), ["ALL"]);
        assert_eq!(value(&a, "--security-opt"), ["no-new-privileges"]);
        assert!(a.contains(&"--read-only".to_string()) && a.contains(&"--rm".to_string()));
        assert_eq!(value(&a, "--pull"), ["never"], "the image is never pulled");
        assert_eq!(value(&a, "--memory"), value(&a, "--memory-swap"), "no swap");
        assert_eq!(
            (value(&a, "--pids-limit"), value(&a, "--cpus")),
            (vec!["128"], vec!["1"])
        );
        assert_eq!(value(&a, "--hostname"), ["plc-gw-03"]);
        assert_eq!(value(&a, "--name"), ["hp-test"]);
        assert!(
            value(&a, "--label").contains(&"honeypot.managed=true"),
            "so a reaper can find it"
        );
        assert!(!a.iter().any(|x| x == "--privileged"
            || x.starts_with("--cap-add")
            || x.starts_with("--volume")
            || x == "-v"));
        let tmpfs = value(&a, "--tmpfs");
        assert!(tmpfs.contains(&"/tmp:rw,exec,nosuid,size=64m"), "{tmpfs:?}");
        assert!(
            tmpfs
                .iter()
                .all(|t| t.contains("nosuid") && t.contains("size=")),
            "every writable dir is capped"
        );
    }

    #[test]
    fn the_image_and_runtime_come_from_the_policy() {
        let a = args(&request());
        assert!(!a.contains(&"--runtime".to_string()));
        assert!(a.contains(&"honeypot/test:1".to_string()));
        let p = Policy::parse(&format!("{TEST_POLICY}runtime: runsc")).unwrap();
        let a = plan(&p, &request(), "n").unwrap().args;
        assert_eq!(value(&a, "--runtime"), ["runsc"]);
    }

    #[test]
    fn what_runs_in_each_of_the_four_modes() {
        let tail = |req: &Request| -> Vec<String> {
            let a = args(req);
            a[a.iter().position(|x| x == "honeypot/test:1").unwrap() + 1..].to_vec()
        };
        assert_eq!(tail(&request()), ["/bin/bash", "-l"]);
        let cmd = Request {
            command: Some("echo hi; id".into()),
            ..request()
        };
        assert_eq!(
            tail(&cmd),
            ["/bin/bash", "-c", "echo hi; id"],
            "one argument, never re-parsed by a host shell"
        );
        let pty = Request {
            terminal: terminal(100, 30),
            ..request()
        };
        assert_eq!(
            tail(&pty),
            [
                "script",
                "-qec",
                "stty rows 30 cols 100 2>/dev/null; exec /bin/bash -l",
                "/dev/null"
            ]
        );
        let pty_cmd = Request {
            terminal: terminal(100, 30),
            command: Some("id".into()),
            ..request()
        };
        let a = args(&pty_cmd);
        assert!(
            a.contains(&"HP_COMMAND=id".to_string()),
            "the command rides in the environment"
        );
        assert_eq!(
            tail(&pty_cmd)[2],
            "stty rows 30 cols 100 2>/dev/null; c=$HP_COMMAND; unset HP_COMMAND; exec /bin/bash -c \"$c\""
        );
    }

    #[test]
    fn terminal_sizes_are_clamped_and_unset_means_a_sane_default() {
        let size = |c, r| {
            args(&Request {
                terminal: terminal(c, r),
                ..request()
            })
            .iter()
            .find(|x| x.starts_with("stty"))
            .cloned()
            .unwrap()
        };
        assert!(size(0, 0).starts_with("stty rows 24 cols 80"));
        assert!(size(u16::MAX, u16::MAX).starts_with("stty rows 500 cols 500"));
    }

    #[test]
    fn only_listed_accounts_are_honoured() {
        let user = |u: &str| {
            value(
                &args(&Request {
                    user: u.into(),
                    ..request()
                }),
                "--user",
            )
            .join(",")
        };
        assert_eq!(user("admin"), "admin");
        assert_eq!(user("root"), "root");
        assert_eq!(
            user("operator"),
            "root",
            "unlisted accounts fall back to the default"
        );
        assert_eq!(user("root --privileged"), "root");
        assert_eq!(user("-v"), "root");
        assert_eq!(user(""), "root");
    }

    /// The property that matters: whatever the peer sends, the *set of flags*
    /// is exactly the policy's. Hostile text can only ever appear as one
    /// designated value, never as a flag of its own.
    #[test]
    fn no_request_can_add_or_change_a_flag() {
        let image = |a: &[String]| a.iter().position(|x| x == "honeypot/test:1").unwrap();
        let flag_names = |a: &[String]| -> std::collections::BTreeSet<String> {
            a[..image(a)]
                .iter()
                .filter(|x| x.starts_with('-'))
                .cloned()
                .collect()
        };
        let baseline = flag_names(&args(&request()));
        let evil = [
            "--privileged",
            "-v /:/host",
            "x\n--network host",
            "'; reboot; '",
            "$(id)",
            "--cap-add=ALL",
            "../../etc",
            "a b",
            "\u{0}",
        ];
        for e in evil {
            let clean = e.replace('\0', "");
            let term = Terminal {
                term: e.into(),
                cols: 80,
                rows: 24,
            };
            for req in [
                Request {
                    user: e.into(),
                    ..request()
                },
                Request {
                    session_id: e.into(),
                    ..request()
                },
                Request {
                    command: Some(clean.clone()),
                    ..request()
                },
                Request {
                    terminal: Some(term),
                    command: Some(clean),
                    ..request()
                },
            ] {
                let a = args(&req);
                assert_eq!(flag_names(&a), baseline, "flags changed for {e:?}");
                assert_eq!(value(&a, "--network"), ["none"]);
                assert_eq!(value(&a, "--cap-drop"), ["ALL"]);
                // every argument before the image is a flag or the value that follows one
                for (i, x) in a[..image(&a)].iter().enumerate() {
                    assert!(
                        x.starts_with('-') || a[i - 1].starts_with('-'),
                        "{x:?} floats free in {e:?}"
                    );
                }
                // and the only environment a peer can influence is these three
                for v in value(&a, "--env") {
                    assert!(
                        ["TERM=", "LANG=", "HP_COMMAND="]
                            .iter()
                            .any(|p| v.starts_with(p)),
                        "{v:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn hostile_terminal_types_and_session_ids_are_replaced_not_passed() {
        let a = args(&Request {
            terminal: Some(Terminal {
                term: "xterm --privileged".into(),
                cols: 80,
                rows: 24,
            }),
            session_id: "x --privileged".into(),
            ..request()
        });
        assert!(a.contains(&"TERM=xterm".to_string()));
        assert!(a.contains(&"honeypot.session=unknown".to_string()));
        assert!(!a.iter().any(|x| x.contains("privileged")));
        let a = args(&Request {
            terminal: Some(Terminal {
                term: "screen-256color".into(),
                cols: 80,
                rows: 24,
            }),
            ..request()
        });
        assert!(
            a.contains(&"TERM=screen-256color".to_string()),
            "ordinary terminals are kept"
        );
    }

    #[test]
    fn unusable_commands_are_rejected_before_anything_starts() {
        let plan_cmd = |c: String| {
            plan(
                &policy(),
                &Request {
                    command: Some(c),
                    ..request()
                },
                "n",
            )
        };
        assert_eq!(
            plan_cmd("a\0b".into()),
            Err(Rejected("command contains a NUL byte"))
        );
        assert_eq!(
            plan_cmd("x".repeat(MAX_COMMAND + 1)),
            Err(Rejected("command too long"))
        );
        assert!(plan_cmd("x".repeat(MAX_COMMAND)).is_ok());
    }
}
