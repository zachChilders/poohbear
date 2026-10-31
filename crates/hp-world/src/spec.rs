//! The host spec: a YAML description of the emulated machine, validated at
//! load (like tracks), plus the code that seeds a believable filesystem from
//! it. Operators describe *what the machine is*; no per-command scripting.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::fs::{normalize, split, Fs, Meta};

/// The built-in host, used when no `host:` file is configured.
pub const DEFAULT_HOST: &str = include_str!("../hosts/default.yaml");

/// mtime for seeded files: a plausible install date.
pub(crate) const SEED_TIME: i64 = 1_729_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub hostname: String,
    pub os: Os,
    pub kernel: Kernel,
    pub uptime_secs: u64,
    pub cpu: Cpu,
    pub memory_kb: Memory,
    /// Where interactive logins appear to come from (for `w`).
    #[serde(default = "default_login_from")]
    pub login_from: String,
    pub users: Vec<Account>,
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub processes: Vec<Process>,
    #[serde(default)]
    pub dirs: Vec<String>,
    /// Extra files (path -> content); parent directories are created.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

fn default_login_from() -> String {
    "10.0.0.2".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Os {
    pub id: String,
    pub name: String,
    pub pretty_name: String,
    pub version: String,
    pub version_id: String,
    pub codename: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    pub release: String,
    pub version: String,
    pub machine: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cpu {
    pub model: String,
    pub cores: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub total: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub home: String,
    #[serde(default = "default_shell")]
    pub shell: String,
    /// Supplementary groups. `sudo` grants sudo.
    #[serde(default)]
    pub groups: Vec<String>,
}

fn default_shell() -> String {
    "/bin/bash".into()
}

impl Account {
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    pub fn can_sudo(&self) -> bool {
        self.is_root() || self.groups.iter().any(|g| g == "sudo")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub addr: String,
    pub netmask: String,
    #[serde(default)]
    pub mac: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub user: String,
    pub pid: u32,
    pub cmd: String,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

impl HostSpec {
    pub fn load(path: &Path) -> anyhow::Result<HostSpec> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading host spec {}", path.display()))?;
        HostSpec::parse(&text)
    }

    pub fn default_host() -> HostSpec {
        HostSpec::parse(DEFAULT_HOST).expect("the built-in host spec is valid")
    }

    /// Parse and validate. Every problem is reported at once.
    pub fn parse(text: &str) -> anyhow::Result<HostSpec> {
        let spec: HostSpec = serde_yaml::from_str(text).context("parsing host spec")?;
        let mut errs = Vec::new();
        if !valid_name(&spec.hostname) {
            errs.push(format!(
                "hostname {:?} is not a valid host name",
                spec.hostname
            ));
        }
        if spec.cpu.cores == 0 {
            errs.push("cpu.cores must be at least 1".into());
        }
        if spec.memory_kb.free > spec.memory_kb.total {
            errs.push("memory_kb.free exceeds memory_kb.total".into());
        }
        if !spec.users.iter().any(|u| u.uid == 0 && u.name == "root") {
            errs.push("users must include `root` with uid 0".into());
        }
        let mut seen = BTreeSet::new();
        for u in &spec.users {
            if !valid_name(&u.name) {
                errs.push(format!("user name {:?} is not valid", u.name));
            }
            if !seen.insert(&u.name) {
                errs.push(format!("duplicate user {:?}", u.name));
            }
            if !u.home.starts_with('/') || normalize("/", &u.home) != u.home {
                errs.push(format!(
                    "user {}: home {:?} must be a normalized absolute path",
                    u.name, u.home
                ));
            }
        }
        let known: BTreeSet<_> = spec.users.iter().map(|u| u.name.as_str()).collect();
        for p in &spec.processes {
            if !known.contains(p.user.as_str()) {
                errs.push(format!(
                    "process {} runs as unknown user {:?}",
                    p.pid, p.user
                ));
            }
        }
        for path in spec.dirs.iter().chain(spec.files.keys()) {
            if !path.starts_with('/') || normalize("/", path) != *path || path == "/" {
                errs.push(format!("path {path:?} must be a normalized absolute path"));
            }
        }
        if !errs.is_empty() {
            bail!(
                "invalid host spec ({} problem(s)):\n  - {}",
                errs.len(),
                errs.join("\n  - ")
            );
        }
        Ok(spec)
    }

    pub fn account(&self, name: &str) -> Option<&Account> {
        self.users.iter().find(|u| u.name == name)
    }

    /// Who should own `path`: the user whose home contains it, else root.
    fn owner_of(&self, path: &str) -> (&str, &str) {
        for u in &self.users {
            if !u.is_root() && (path == u.home || path.starts_with(&format!("{}/", u.home))) {
                return (&u.name, &u.name);
            }
        }
        ("root", "root")
    }

    /// Seed a filesystem: the standard skeleton, files derived from this
    /// spec, each user's home, then the spec's own `dirs` and `files`.
    pub fn build_fs(&self) -> Fs {
        let meta = |owner: &str, group: &str, mode: u32| Meta {
            mode,
            owner: owner.into(),
            group: group.into(),
            mtime: SEED_TIME,
        };
        let root = |mode| meta("root", "root", mode);
        let mut fs = Fs::new(root(0o755));

        for dir in [
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/etc/cron.d",
            "/etc/ssh",
            "/home",
            "/lib",
            "/media",
            "/mnt",
            "/opt",
            "/proc",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/usr",
            "/usr/bin",
            "/usr/lib",
            "/usr/local",
            "/usr/sbin",
            "/usr/share",
            "/var",
            "/var/backups",
            "/var/log",
            "/var/mail",
            "/var/spool",
            "/var/lib",
        ] {
            fs.mkdir_p(dir, &root(0o755)).expect("skeleton fits");
        }
        fs.mkdir_p("/tmp", &root(0o1777)).expect("skeleton fits");
        fs.mkdir_p("/var/tmp", &root(0o1777))
            .expect("skeleton fits");
        fs.mkdir_p("/root", &root(0o700)).expect("skeleton fits");

        let put = |fs: &mut Fs, path: &str, content: String, m: Meta| {
            let (parent, _) = split(path).expect("file paths have a parent");
            fs.mkdir_p(parent, &root(0o755)).expect("parents fit");
            fs.write(path, content.as_bytes(), false, m)
                .expect("seed file fits");
        };

        put(
            &mut fs,
            "/etc/hostname",
            format!("{}\n", self.hostname),
            root(0o644),
        );
        put(
            &mut fs,
            "/etc/hosts",
            format!(
                "127.0.0.1 localhost\n127.0.1.1 {}\n\n::1 ip6-localhost ip6-loopback\n",
                self.hostname
            ),
            root(0o644),
        );
        put(&mut fs, "/etc/passwd", self.passwd(), root(0o644));
        put(&mut fs, "/etc/group", self.group(), root(0o644));
        put(
            &mut fs,
            "/etc/shadow",
            self.shadow(),
            meta("root", "shadow", 0o640),
        );
        put(&mut fs, "/etc/os-release", self.os_release(), root(0o644));
        put(
            &mut fs,
            "/etc/issue",
            format!("{} \\n \\l\n\n", self.os.pretty_name),
            root(0o644),
        );
        put(&mut fs, "/proc/version", format!("Linux version {} (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) {}\n", self.kernel.release, self.kernel.version), root(0o444));
        put(&mut fs, "/proc/cpuinfo", self.cpuinfo(), root(0o444));
        put(&mut fs, "/proc/meminfo", self.meminfo(), root(0o444));
        put(
            &mut fs,
            "/proc/uptime",
            format!(
                "{}.42 {}.18\n",
                self.uptime_secs,
                self.uptime_secs * 2 - 1000
            ),
            root(0o444),
        );

        for u in &self.users {
            let (owner, group) = if u.is_root() {
                ("root", "root")
            } else {
                (u.name.as_str(), u.name.as_str())
            };
            let mode = if u.is_root() { 0o700 } else { 0o750 };
            fs.mkdir_p(&u.home, &meta(owner, group, mode))
                .expect("home fits");
            for (name, text) in [
                (".bashrc", BASHRC),
                (".profile", PROFILE),
                (".bash_logout", BASH_LOGOUT),
            ] {
                put(
                    &mut fs,
                    &format!("{}/{name}", u.home),
                    text.to_string(),
                    meta(owner, group, 0o644),
                );
            }
        }

        for dir in &self.dirs {
            let (o, g) = self.owner_of(dir);
            fs.mkdir_p(dir, &meta(o, g, 0o755)).expect("spec dir fits");
        }
        for (path, content) in &self.files {
            let (o, g) = self.owner_of(path);
            let mode = if path.ends_with(".py") || path.ends_with(".sh") {
                0o755
            } else {
                0o644
            };
            put(&mut fs, path, content.clone(), meta(o, g, mode));
        }
        fs
    }

    fn passwd(&self) -> String {
        let mut out = String::new();
        for (name, uid, home, shell) in [
            ("root", 0, "/root", "/bin/bash"),
            ("daemon", 1, "/usr/sbin", "/usr/sbin/nologin"),
            ("bin", 2, "/bin", "/usr/sbin/nologin"),
            ("sys", 3, "/dev", "/usr/sbin/nologin"),
            ("sync", 4, "/bin", "/bin/sync"),
            ("man", 6, "/var/cache/man", "/usr/sbin/nologin"),
            ("lp", 7, "/var/spool/lpd", "/usr/sbin/nologin"),
            ("mail", 8, "/var/mail", "/usr/sbin/nologin"),
            ("www-data", 33, "/var/www", "/usr/sbin/nologin"),
            ("nobody", 65534, "/nonexistent", "/usr/sbin/nologin"),
            ("sshd", 105, "/run/sshd", "/usr/sbin/nologin"),
        ] {
            // The spec's own definition of a user wins over the generated one.
            if self.account(name).is_none() {
                out.push_str(&format!("{name}:x:{uid}:{uid}:{name}:{home}:{shell}\n"));
            }
        }
        for u in &self.users {
            let gecos = if u.is_root() { "root" } else { &u.name };
            out.push_str(&format!(
                "{}:x:{}:{}:{gecos}:{}:{}\n",
                u.name, u.uid, u.uid, u.home, u.shell
            ));
        }
        // root first, like a real file
        let mut lines: Vec<&str> = out.lines().collect();
        lines.sort_by_key(|l| {
            l.split(':')
                .nth(2)
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(u32::MAX)
        });
        lines.join("\n") + "\n"
    }

    fn group(&self) -> String {
        let mut out =
            String::from("root:x:0:\ndaemon:x:1:\nsudo:x:27:\nshadow:x:42:\nnogroup:x:65534:\n");
        let mut extra: BTreeSet<&str> = BTreeSet::new();
        for u in self.users.iter().filter(|u| !u.is_root()) {
            out.push_str(&format!("{}:x:{}:\n", u.name, u.uid));
            extra.extend(
                u.groups
                    .iter()
                    .map(String::as_str)
                    .filter(|g| *g != u.name && *g != "sudo"),
            );
        }
        for (i, g) in extra.iter().enumerate() {
            let members: Vec<_> = self
                .users
                .iter()
                .filter(|u| u.groups.iter().any(|x| x == g))
                .map(|u| u.name.as_str())
                .collect();
            out.push_str(&format!("{g}:x:{}:{}\n", 20 + i, members.join(",")));
        }
        out
    }

    fn shadow(&self) -> String {
        let mut out = String::new();
        for u in &self.users {
            // Locked/unusable hashes: there is nothing to crack.
            out.push_str(&format!("{}:!:19650:0:99999:7:::\n", u.name));
        }
        out
    }

    fn os_release(&self) -> String {
        let o = &self.os;
        format!(
            "PRETTY_NAME=\"{}\"\nNAME=\"{}\"\nVERSION_ID=\"{}\"\nVERSION=\"{}\"\nVERSION_CODENAME={}\nID={}\nID_LIKE=debian\nHOME_URL=\"https://www.ubuntu.com/\"\nSUPPORT_URL=\"https://help.ubuntu.com/\"\nBUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\nUBUNTU_CODENAME={}\n",
            o.pretty_name, o.name, o.version_id, o.version, o.codename, o.id, o.codename
        )
    }

    fn cpuinfo(&self) -> String {
        (0..self.cpu.cores)
            .map(|i| {
                format!(
                    "processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 79\nmodel name\t: {}\nstepping\t: 1\ncpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\ncpu cores\t: {}\nbogomips\t: 4799.99\n\n",
                    self.cpu.model, self.cpu.cores
                )
            })
            .collect()
    }

    fn meminfo(&self) -> String {
        let m = &self.memory_kb;
        format!(
            "MemTotal:       {:>8} kB\nMemFree:        {:>8} kB\nMemAvailable:   {:>8} kB\nBuffers:        {:>8} kB\nCached:         {:>8} kB\nSwapTotal:      {:>8} kB\nSwapFree:       {:>8} kB\n",
            m.total, m.free, m.free + m.total / 8, m.total / 40, m.total / 6, 2097148, 2097148
        )
    }
}

const BASHRC: &str = "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n# If not running interactively, don't do anything\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\n\nHISTCONTROL=ignoreboth\nshopt -s histappend\nHISTSIZE=1000\nHISTFILESIZE=2000\n";
const PROFILE: &str = "# ~/.profile: executed by the command interpreter for login shells.\n\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n        . \"$HOME/.bashrc\"\n    fi\nfi\n\nif [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\n";
const BASH_LOGOUT: &str = "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\nif [ \"$SHLVL\" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Actor;

    fn spec() -> HostSpec {
        HostSpec::default_host()
    }

    #[test]
    fn the_builtin_host_is_valid_and_seeds_a_realistic_filesystem() {
        let s = spec();
        let fs = s.build_fs();
        assert_eq!(fs.read("/etc/hostname").unwrap(), b"plc-gw-03\n");
        let passwd = String::from_utf8(fs.read("/etc/passwd").unwrap().to_vec()).unwrap();
        assert!(
            passwd.starts_with("root:x:0:0:root:/root:/bin/bash\n"),
            "{passwd}"
        );
        assert!(passwd.contains("admin:x:1000:1000:admin:/home/admin:/bin/bash\n"));
        assert_eq!(
            passwd.lines().filter(|l| l.starts_with("root:")).count(),
            1,
            "no duplicate root"
        );
        assert!(String::from_utf8_lossy(fs.read("/etc/os-release").unwrap())
            .contains("VERSION_ID=\"22.04\""));
        assert!(
            String::from_utf8_lossy(fs.read("/proc/cpuinfo").unwrap())
                .matches("processor")
                .count()
                == 2
        );
        assert!(fs.exists("/home/admin/.bashrc") && fs.exists("/home/operator/.profile"));
        assert!(
            String::from_utf8_lossy(fs.read("/home/admin/notes.txt").unwrap())
                .contains("rotate historian")
        );
    }

    #[test]
    fn ownership_and_modes_look_right() {
        let fs = spec().build_fs();
        let admin = Actor { name: "admin" };
        assert!(!fs.can_read("/etc/shadow", admin), "shadow is root-only");
        assert!(fs.can_write("/home/admin/x", admin));
        assert!(!fs.can_write("/root/x", admin));
        assert!(!fs.can_read("/root/.bashrc", admin), "root's home is 0700");
        assert_eq!(
            fs.node("/home/admin/notes.txt").unwrap().meta.owner,
            "admin"
        );
        assert_eq!(fs.node("/opt/plc/gateway.py").unwrap().meta.mode, 0o755);
        assert_eq!(fs.node("/tmp").unwrap().meta.mode, 0o1777);
    }

    #[test]
    fn group_file_includes_supplementary_groups_with_members() {
        let g = spec().group();
        assert!(
            g.contains("sudo:x:27:\n"),
            "admin is deliberately not a sudoer: {g}"
        );
        assert!(g.contains("dialout:x:") && g.contains(":admin\n"), "{g}");
        assert!(g.contains("admin:x:1000:\n"));
    }

    #[test]
    fn sudo_rights_come_from_the_sudo_group() {
        let s = spec();
        assert!(s.account("root").unwrap().can_sudo());
        assert!(!s.account("admin").unwrap().can_sudo());
        assert!(
            s.account("nobody").is_none(),
            "only spec users are accounts"
        );
    }

    #[test]
    fn invalid_specs_report_every_problem() {
        let bad = DEFAULT_HOST
            .replace("hostname: plc-gw-03", "hostname: \"bad host!\"")
            .replace(
                "{ name: root, uid: 0, home: /root }",
                "{ name: toor, uid: 5, home: root }",
            )
            .replace("user: root, pid: 1,", "user: ghost, pid: 1,")
            .replace("  - /opt/plc\n", "  - opt/plc\n");
        let e = HostSpec::parse(&bad).unwrap_err().to_string();
        for want in [
            "not a valid host name",
            "must include `root`",
            "must be a normalized absolute path",
            "unknown user \"ghost\"",
            "opt/plc",
        ] {
            assert!(e.contains(want), "missing {want:?} in {e}");
        }
    }

    #[test]
    fn rejects_unknown_fields_duplicates_and_bad_numbers() {
        assert!(HostSpec::parse(&format!("{DEFAULT_HOST}\nbogus: 1\n")).is_err());
        let dup = DEFAULT_HOST.replace("operator", "admin");
        assert!(HostSpec::parse(&dup)
            .unwrap_err()
            .to_string()
            .contains("duplicate user"));
        let mem = DEFAULT_HOST.replace("free: 1203412", "free: 99999999");
        assert!(HostSpec::parse(&mem)
            .unwrap_err()
            .to_string()
            .contains("memory_kb.free"));
        let cores = DEFAULT_HOST.replace("cores: 2", "cores: 0");
        assert!(HostSpec::parse(&cores)
            .unwrap_err()
            .to_string()
            .contains("cpu.cores"));
    }

    #[test]
    fn load_reads_files_and_reports_missing_ones() {
        let dir = std::env::temp_dir().join(format!("hp-world-spec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.yaml");
        std::fs::write(&path, DEFAULT_HOST).unwrap();
        assert_eq!(HostSpec::load(&path).unwrap().hostname, "plc-gw-03");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(HostSpec::load(&path)
            .unwrap_err()
            .to_string()
            .contains("reading host spec"));
    }
}
