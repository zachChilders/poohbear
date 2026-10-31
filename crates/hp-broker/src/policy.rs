//! What the operator allows. Loaded and validated at startup; the broker
//! refuses to start on a bad policy, and unknown fields are rejected, so a
//! typo cannot silently loosen anything.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Where to listen. Its directory should already be restricted to the
    /// honeypot's user: the socket is created with the umask's permissions
    /// and then narrowed to `socket_mode`.
    pub socket: PathBuf,
    /// Octal permission bits for the socket.
    #[serde(default = "default_socket_mode")]
    pub socket_mode: String,
    /// The container CLI. A path or a name on `PATH`.
    #[serde(default = "default_docker")]
    pub docker: String,
    /// The image every sandbox starts from. It is never pulled.
    pub image: String,
    /// OCI runtime, e.g. `runsc` for gVisor. Unset uses the daemon's default.
    pub runtime: Option<String>,
    /// The host name the shell sees.
    pub hostname: String,
    /// Accounts a login may map to. Anything else gets `default_user`.
    #[serde(default = "default_users")]
    pub users: Vec<String>,
    #[serde(default = "default_user")]
    pub default_user: String,
    /// The shell to run, as an absolute path in the image.
    #[serde(default = "default_shell")]
    pub shell: String,
    #[serde(default)]
    pub limits: Limits,
    /// Directories that are writable (as size-capped tmpfs); the rest of the
    /// filesystem is read-only.
    #[serde(default = "default_writable")]
    pub writable: Vec<String>,
    /// Sandboxes that may exist at once.
    #[serde(default = "default_max_sandboxes")]
    pub max_sandboxes: usize,
    /// Longest a sandbox may live, whatever it is doing.
    #[serde(default = "default_session_timeout")]
    pub session_timeout: String,
    /// How long a sandbox may keep running after the peer closes its input.
    #[serde(default = "default_linger")]
    pub linger: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_cpus")]
    pub cpus: f32,
    /// Memory (and, with no swap, the most it can use), e.g. `256m`.
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_pids")]
    pub pids: u32,
    /// Size of each writable tmpfs, e.g. `64m`.
    #[serde(default = "default_tmpfs")]
    pub tmpfs: String,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            cpus: default_cpus(),
            memory: default_memory(),
            pids: default_pids(),
            tmpfs: default_tmpfs(),
        }
    }
}

fn default_socket_mode() -> String {
    "660".into()
}
fn default_docker() -> String {
    "docker".into()
}
fn default_users() -> Vec<String> {
    vec!["root".into()]
}
fn default_user() -> String {
    "root".into()
}
fn default_shell() -> String {
    "/bin/bash".into()
}
fn default_cpus() -> f32 {
    1.0
}
fn default_memory() -> String {
    "256m".into()
}
fn default_pids() -> u32 {
    128
}
fn default_tmpfs() -> String {
    "64m".into()
}
fn default_writable() -> Vec<String> {
    ["/tmp", "/var/tmp", "/root", "/home", "/run"]
        .map(String::from)
        .to_vec()
}
fn default_max_sandboxes() -> usize {
    16
}
fn default_session_timeout() -> String {
    "15m".into()
}
fn default_linger() -> String {
    "2m".into()
}

/// A name that is safe to pass as an argument: no leading `-`, no spaces.
pub(crate) fn safe(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).expect("static pattern").is_match(value)
}

impl Policy {
    pub fn load(path: &Path) -> anyhow::Result<Policy> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Policy::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Policy> {
        let p: Policy = serde_yaml::from_str(text).context("parsing the policy")?;
        let mut errs = Vec::new();
        let mut check = |ok: bool, msg: String| {
            if !ok {
                errs.push(msg);
            }
        };
        check(
            u32::from_str_radix(&p.socket_mode, 8).is_ok_and(|m| m <= 0o777),
            format!(
                "socket_mode {:?} is not octal permission bits",
                p.socket_mode
            ),
        );
        check(
            safe(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$", &p.docker),
            format!("docker {:?} is not a plain command or path", p.docker),
        );
        check(
            safe(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$", &p.image),
            format!("image {:?} is not a plain image reference", p.image),
        );
        check(
            p.runtime
                .as_ref()
                .is_none_or(|r| safe(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", r)),
            "runtime is not a plain name".into(),
        );
        check(
            safe(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$", &p.hostname),
            format!("hostname {:?} is not a valid host name", p.hostname),
        );
        check(
            !p.users.is_empty() && p.users.iter().all(|u| valid_user(u)),
            "users must be valid account names".into(),
        );
        check(
            valid_user(&p.default_user),
            format!(
                "default_user {:?} is not a valid account name",
                p.default_user
            ),
        );
        check(
            safe(r"^/[A-Za-z0-9._/-]{1,127}$", &p.shell),
            format!("shell {:?} is not an absolute path", p.shell),
        );
        check(
            p.limits.cpus > 0.0 && p.limits.cpus <= 64.0,
            "limits.cpus must be between 0 and 64".into(),
        );
        check(
            safe(r"^[1-9][0-9]{0,5}[kmg]$", &p.limits.memory),
            format!("limits.memory {:?} must look like 256m", p.limits.memory),
        );
        check(
            safe(r"^[1-9][0-9]{0,5}[kmg]$", &p.limits.tmpfs),
            format!("limits.tmpfs {:?} must look like 64m", p.limits.tmpfs),
        );
        check(
            (1..=100_000).contains(&p.limits.pids),
            "limits.pids must be between 1 and 100000".into(),
        );
        check(
            p.writable
                .iter()
                .all(|w| safe(r"^/[A-Za-z0-9._/-]{0,127}$", w) && !w.contains("..") && w != "/"),
            "writable entries must be absolute paths other than /".into(),
        );
        check(
            p.max_sandboxes > 0,
            "max_sandboxes must be at least 1".into(),
        );
        check(
            humantime::parse_duration(&p.session_timeout).is_ok(),
            format!("session_timeout {:?} is not a duration", p.session_timeout),
        );
        check(
            humantime::parse_duration(&p.linger).is_ok(),
            format!("linger {:?} is not a duration", p.linger),
        );
        if !errs.is_empty() {
            bail!(
                "invalid policy ({} problem(s)):\n  - {}",
                errs.len(),
                errs.join("\n  - ")
            );
        }
        Ok(p)
    }

    pub fn session_timeout(&self) -> Duration {
        humantime::parse_duration(&self.session_timeout).expect("validated")
    }

    pub fn linger(&self) -> Duration {
        humantime::parse_duration(&self.linger).expect("validated")
    }

    pub fn socket_mode(&self) -> u32 {
        u32::from_str_radix(&self.socket_mode, 8).expect("validated")
    }
}

pub(crate) fn valid_user(name: &str) -> bool {
    safe(r"^[a-z_][a-z0-9_-]{0,31}$", name)
}

#[cfg(test)]
pub(crate) const TEST_POLICY: &str = "
socket: /tmp/hp-test.sock
image: honeypot/test:1
hostname: plc-gw-03
users: [root, admin]
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_safe_ones() {
        let p = Policy::parse(TEST_POLICY).unwrap();
        assert_eq!(
            (p.max_sandboxes, p.limits.pids, p.limits.memory.as_str()),
            (16, 128, "256m")
        );
        assert_eq!(
            (p.session_timeout(), p.linger(), p.socket_mode()),
            (Duration::from_secs(900), Duration::from_secs(120), 0o660)
        );
        assert!(
            p.writable.contains(&"/tmp".to_string()) && !p.writable.contains(&"/etc".to_string())
        );
        assert_eq!(p.docker, "docker");
    }

    #[test]
    fn a_policy_cannot_smuggle_flags_or_loosen_things() {
        let base = |extra: &str| format!("{TEST_POLICY}{extra}");
        for (extra, want) in [
            ("network: host", "network"), // unknown field: there is no way to enable networking
            ("privileged: true", "privileged"),
            ("docker: '--privileged'", "docker"),
            ("runtime: '--cap-add=ALL'", "runtime"),
            ("shell: bash", "shell"),
            ("default_user: 'root --privileged'", "default_user"),
            ("users: [Root]", "users"),
            ("writable: ['/']", "writable"),
            ("writable: ['/tmp/../etc']", "writable"),
            ("limits: { memory: '0' }", "memory"),
            ("limits: { memory: '1g --privileged' }", "memory"),
            ("limits: { cpus: 0 }", "cpus"),
            ("limits: { pids: 0 }", "pids"),
            ("max_sandboxes: 0", "max_sandboxes"),
            ("session_timeout: soon", "session_timeout"),
            ("socket_mode: '999'", "socket_mode"),
        ] {
            let e = format!("{:#}", Policy::parse(&base(extra)).unwrap_err());
            assert!(e.contains(want), "{extra} -> {e}");
        }
        assert!(Policy::parse("socket: /s\nimage: '-v /:/host'\nhostname: h").is_err());
        assert!(Policy::parse("socket: /s\nimage: ok\nhostname: 'bad host'").is_err());
        assert!(
            Policy::parse("image: ok\nhostname: h").is_err(),
            "the socket is required"
        );
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let e = Policy::parse("socket: /s\nimage: '-x'\nhostname: 'b h'\nmax_sandboxes: 0")
            .unwrap_err()
            .to_string();
        assert!(e.contains("3 problem(s)"), "{e}");
    }

    #[test]
    fn load_reads_a_file() {
        let path = std::env::temp_dir().join(format!("hp-policy-{}.yaml", std::process::id()));
        std::fs::write(&path, TEST_POLICY).unwrap();
        assert_eq!(Policy::load(&path).unwrap().hostname, "plc-gw-03");
        std::fs::remove_file(&path).unwrap();
        assert!(Policy::load(&path).is_err());
    }
}
