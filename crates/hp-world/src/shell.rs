//! The shell: per-session state, and execution of parsed command lines.
//!
//! Nothing here touches the real machine. "Running" a command means reading
//! and writing the session's in-memory [`Fs`] and producing text. Downloads
//! never use the network (see `cmds::net`); executing a file does nothing but
//! raise a tag so it is flagged.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hp_core::{Host, HostFactory, HostReply};

use crate::cmds::{self, Streams};
use crate::fs::{normalize, Actor, Fs, FsError, Meta};
use crate::parse::{self, Command, Join, Pipeline, Redir, Word};
use crate::spec::{Account, HostSpec};
use crate::timefmt;

/// Most output a single line may produce.
const MAX_OUTPUT: usize = 256 * 1024;
/// Nesting limit for `sh -c`, `sudo`, `nohup`, ...
const MAX_DEPTH: usize = 4;
const MAX_HISTORY: usize = 500;

/// Seconds since the epoch; injectable so tests are deterministic.
pub type Clock = Box<dyn Fn() -> i64 + Send>;

pub fn system_clock() -> Clock {
    Box::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
    })
}

pub struct Shell {
    pub(crate) spec: Arc<HostSpec>,
    pub(crate) fs: Fs,
    pub(crate) user: Account,
    pub(crate) cwd: String,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) history: Vec<String>,
    /// Tags raised while running the current line.
    pub(crate) tags: Vec<String>,
    pub(crate) exit: bool,
    /// Files the peer created or modified this session, as opposed to ones
    /// that came with the host. Running one of these is what gets flagged.
    pub(crate) created: BTreeSet<String>,
    pub(crate) last_status: i32,
    pub(crate) depth: usize,
    /// The previous command in this pipeline wrote downloaded content to
    /// stdout (`curl url | sh`), so a shell reading it is running a payload.
    pub(crate) pipe_from_fetch: bool,
    /// Uptime in seconds at the moment the session started.
    uptime_base: u64,
    born: i64,
    clock: Clock,
}

impl Shell {
    pub fn new(spec: Arc<HostSpec>, clock: Clock, uptime_base: u64) -> Shell {
        let fs = spec.build_fs();
        let root = spec.account("root").expect("validated").clone();
        let born = clock();
        let mut sh = Shell {
            pipe_from_fetch: false,
            uptime_base,
            born,
            cwd: root.home.clone(),
            user: root,
            spec,
            fs,
            env: BTreeMap::new(),
            history: Vec::new(),
            tags: Vec::new(),
            exit: false,
            created: BTreeSet::new(),
            last_status: 0,
            depth: 0,
            clock,
        };
        sh.reset_env();
        sh
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Seconds the machine has been up, growing for the life of the session.
    pub(crate) fn uptime_secs(&self) -> u64 {
        self.uptime_base + u64::try_from((self.now() - self.born).max(0)).unwrap_or(0)
    }

    pub(crate) fn actor(&self) -> Actor<'_> {
        Actor {
            name: &self.user.name,
        }
    }

    pub(crate) fn abs(&self, path: &str) -> String {
        normalize(&self.cwd, path)
    }

    pub(crate) fn tag(&mut self, tag: &str) {
        if !self.tags.iter().any(|t| t == tag) {
            self.tags.push(tag.to_string());
        }
    }

    /// Metadata for a file the current user is creating now.
    pub(crate) fn new_meta(&self, mode: u32) -> Meta {
        Meta {
            mode,
            owner: self.user.name.clone(),
            group: self.user.name.clone(),
            mtime: self.now(),
        }
    }

    fn reset_env(&mut self) {
        let home = self.user.home.clone();
        let env = &mut self.env;
        env.clear();
        for (k, v) in [
            ("HOME", home.as_str()),
            ("USER", &self.user.name),
            ("LOGNAME", &self.user.name),
            ("SHELL", &self.user.shell),
            ("PWD", &home),
            ("HOSTNAME", &self.spec.hostname),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "xterm"),
            ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"),
        ] {
            env.insert(k.to_string(), v.to_string());
        }
    }

    /// Log in as `name`. Unknown names get a plausible account, because by the
    /// time the shell opens the behavior has already decided to let them in.
    pub fn login(&mut self, name: &str) {
        let account = self
            .spec
            .account(name)
            .cloned()
            .unwrap_or_else(|| synthesize(name));
        if !self.fs.exists(&account.home) {
            let meta = Meta {
                mode: 0o750,
                owner: account.name.clone(),
                group: account.name.clone(),
                mtime: self.now(),
            };
            let _ = self.fs.mkdir_p(&account.home, &meta);
        }
        self.cwd = account.home.clone();
        self.user = account;
        self.reset_env();
        self.history.clear();
        self.last_status = 0;
        self.exit = false;
    }

    /// Switch to another account within the session (`sudo -i`, `su`): keeps
    /// history and the filesystem, resets directory and environment.
    pub(crate) fn become_user(&mut self, name: &str) {
        let history = std::mem::take(&mut self.history);
        self.login(name);
        self.history = history;
    }

    /// What an interactive login prints before the first prompt, built from
    /// the spec so it always agrees with `/etc/os-release` and `uname`.
    pub(crate) fn login_banner(&self) -> String {
        let (os, kernel) = (&self.spec.os, &self.spec.kernel);
        // Pretend the last login was a few days ago, from the usual place.
        let last = timefmt::strftime("%a %b %e %H:%M:%S %Y", self.now() - 3 * 86_400 - 4_127);
        format!(
            "Welcome to {} (GNU/Linux {} {})\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/pro\n\nLast login: {last} from {}\n",
            os.pretty_name, kernel.release, kernel.machine, self.spec.login_from
        )
    }

    pub fn prompt(&self) -> String {
        let home = &self.user.home;
        let dir = if self.cwd == *home {
            "~".to_string()
        } else if let Some(rest) = self.cwd.strip_prefix(&format!("{home}/")) {
            format!("~/{rest}")
        } else {
            self.cwd.clone()
        };
        let sigil = if self.user.is_root() { '#' } else { '$' };
        format!("{}@{}:{dir}{sigil} ", self.user.name, self.spec.hostname)
    }

    pub(crate) fn var(&self, name: &str) -> Option<String> {
        match name {
            "?" => Some(self.last_status.to_string()),
            "PWD" => Some(self.cwd.clone()),
            _ => self.env.get(name).cloned(),
        }
    }

    // ---- files -------------------------------------------------------------

    /// Write a file as the current user, with permission checks, raising tags
    /// for writes that look like persistence.
    pub(crate) fn write_file(
        &mut self,
        abs: &str,
        data: &[u8],
        append: bool,
    ) -> Result<(), FsError> {
        // Flag the attempt itself: planting a key that fails because ~/.ssh
        // does not exist is still someone trying to plant a key.
        self.note_write(abs);
        if self.fs.is_dir(abs) {
            return Err(FsError::IsADirectory);
        }
        self.fs.parent_ok(abs)?;
        if !self.fs.can_write(abs, self.actor()) {
            return Err(FsError::Denied);
        }
        let meta = self.new_meta(0o644);
        self.fs.write(abs, data, append, meta)?;
        self.created.insert(abs.to_string());
        Ok(())
    }

    /// Flag writes to places an attacker uses to survive a reboot.
    pub(crate) fn note_write(&mut self, abs: &str) {
        const PREFIXES: [&str; 7] = [
            "/etc/cron",
            "/var/spool/cron",
            "/etc/rc.local",
            "/etc/systemd/system/",
            "/etc/init.d/",
            "/etc/profile",
            "/etc/ld.so.preload",
        ];
        const SUFFIXES: [&str; 5] = [
            "/.ssh/authorized_keys",
            "/.bashrc",
            "/.profile",
            "/.bash_profile",
            "/.bash_logout",
        ];
        if PREFIXES.iter().any(|p| abs.starts_with(p)) || SUFFIXES.iter().any(|s| abs.ends_with(s))
        {
            self.tag("persistence_attempt");
        }
    }

    /// Expand globs in `word` against the filesystem; no match keeps the text.
    fn expand(&self, words: &[Word]) -> Vec<String> {
        let mut out = Vec::new();
        for w in words {
            if w.glob {
                let found = self.glob(&w.text);
                if found.is_empty() {
                    out.push(w.text.clone());
                } else {
                    out.extend(found);
                }
            } else {
                out.push(w.text.clone());
            }
        }
        out
    }

    fn glob(&self, pattern: &str) -> Vec<String> {
        let absolute = pattern.starts_with('/');
        let mut paths: Vec<String> = vec![if absolute { "/".into() } else { String::new() }];
        for comp in pattern.split('/').filter(|c| !c.is_empty()) {
            let mut next = Vec::new();
            for base in &paths {
                let dir = if base.is_empty() {
                    self.cwd.clone()
                } else {
                    self.abs(base)
                };
                if comp.contains(['*', '?', '[']) {
                    if !self.fs.can_read(&dir, self.actor()) {
                        continue;
                    }
                    if let Ok(entries) = self.fs.list(&dir) {
                        for (name, _) in entries {
                            let hidden_ok = comp.starts_with('.') || !name.starts_with('.');
                            if hidden_ok && glob_match(comp, name) {
                                next.push(join_path(base, name));
                            }
                        }
                    }
                } else {
                    next.push(join_path(base, comp));
                }
            }
            paths = next;
        }
        let mut found: Vec<String> = paths
            .into_iter()
            .filter(|p| self.fs.exists(&self.abs(p)))
            .collect();
        found.sort();
        found
    }

    // ---- execution ---------------------------------------------------------

    /// Run one line as typed by the peer.
    pub fn run_line(&mut self, line: &str) -> Vec<u8> {
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.trim().is_empty() {
            self.history.push(line.to_string());
            if self.history.len() > MAX_HISTORY {
                self.history.remove(0);
            }
        }
        let mut out = self.exec_text(line);
        out.truncate(MAX_OUTPUT);
        out
    }

    /// Run `f` one nesting level deeper, refusing past [`MAX_DEPTH`]. Used by
    /// everything that runs another command (`sudo`, `nohup`, `sh -c`).
    pub(crate) fn nested(&mut self, f: impl FnOnce(&mut Shell) -> Streams) -> Streams {
        if self.depth >= MAX_DEPTH {
            return Streams::fail(1, "-bash: maximum nesting depth exceeded");
        }
        self.depth += 1;
        let result = f(self);
        self.depth -= 1;
        result
    }

    /// Parse and run `text` (also used for `sh -c`).
    ///
    /// The line is checked for syntax errors as a whole first, as a shell
    /// does, then run one segment at a time so that each segment expands
    /// variables and `$?` as they are *then*, not as they were when the line
    /// was typed.
    pub(crate) fn exec_text(&mut self, text: &str) -> Vec<u8> {
        if self.depth >= MAX_DEPTH {
            self.last_status = 1;
            return b"-bash: maximum nesting depth exceeded\n".to_vec();
        }
        let home = self.user.home.clone();
        if let Err(e) = parse::parse(text, &|_| None, &home) {
            self.last_status = 2;
            return format!("-bash: {}\n", e.message()).into_bytes();
        }
        self.depth += 1;
        let mut out = Vec::new();
        for (join, segment) in parse::segments(text) {
            match join {
                Join::And if self.last_status != 0 => continue,
                Join::Or if self.last_status == 0 => continue,
                _ => {}
            }
            let home = self.user.home.clone();
            let script = match parse::parse(&segment, &|n| self.var(n), &home) {
                Ok(s) => s,
                Err(e) => {
                    self.last_status = 2;
                    out.extend(format!("-bash: {}\n", e.message()).into_bytes());
                    break;
                }
            };
            for (_, pipeline) in &script.items {
                out.extend(self.exec_pipeline(pipeline));
            }
            if self.exit || out.len() > MAX_OUTPUT {
                break;
            }
        }
        self.depth -= 1;
        out
    }

    fn exec_pipeline(&mut self, pipeline: &Pipeline) -> Vec<u8> {
        let mut terminal = Vec::new();
        let mut piped: Vec<u8> = Vec::new();
        self.pipe_from_fetch = false;
        let last = pipeline.commands.len().saturating_sub(1);
        for (i, command) in pipeline.commands.iter().enumerate() {
            let streams = self.exec_command(command, &piped);
            self.last_status = streams.status;
            terminal.extend(streams.err);
            if i == last {
                terminal.extend(streams.out);
            } else {
                piped = streams.out;
            }
            if self.exit {
                break;
            }
        }
        terminal
    }

    fn exec_command(&mut self, c: &Command, piped: &[u8]) -> Streams {
        let words = self.expand(&c.words);
        let stdin = match &c.stdin {
            None => piped.to_vec(),
            Some(w) => {
                let text = self.expand(std::slice::from_ref(w)).join(" ");
                match self.fs.read(&self.abs(&text)) {
                    Ok(data) => data.to_vec(),
                    Err(e) => return Streams::fail(1, format!("-bash: {text}: {}", e.message())),
                }
            }
        };

        let mut streams = if words.is_empty() {
            Streams::default()
        } else if let Some(first_command) = words.iter().position(|w| !is_assignment(w)) {
            cmds::dispatch(
                self,
                &words[first_command],
                &words[first_command + 1..],
                &stdin,
            )
        } else {
            // only assignments: set them in the shell
            for w in &words {
                let (k, v) = w.split_once('=').expect("is_assignment checked");
                self.env.insert(k.to_string(), v.to_string());
            }
            Streams::default()
        };

        if c.stdout_to_stderr {
            let out = std::mem::take(&mut streams.out);
            streams.err.extend(out);
        }
        if c.stderr_to_stdout {
            let err = std::mem::take(&mut streams.err);
            streams.out.extend(err);
        }
        if let Some(Redir::File { path, append }) = &c.stdout {
            let data = std::mem::take(&mut streams.out);
            self.redirect(path, &data, *append, &mut streams);
        }
        if let Some(Redir::File { path, append }) = &c.stderr {
            let data = std::mem::take(&mut streams.err);
            self.redirect(path, &data, *append, &mut streams);
        }
        streams
    }

    fn redirect(&mut self, target: &Word, data: &[u8], append: bool, streams: &mut Streams) {
        let text = self.expand(std::slice::from_ref(target)).join(" ");
        if text == "/dev/null" {
            return;
        }
        let abs = self.abs(&text);
        if let Err(e) = self.write_file(&abs, data, append) {
            streams
                .err
                .extend(format!("-bash: {text}: {}\n", e.message()).into_bytes());
            streams.status = 1;
        }
    }
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    })
}

fn join_path(base: &str, name: &str) -> String {
    match base {
        "" => name.to_string(),
        "/" => format!("/{name}"),
        _ => format!("{base}/{name}"),
    }
}

/// `*`, `?` and `[...]` (with `!`/`^` negation and ranges) against one name.
pub(crate) fn glob_match(pattern: &str, name: &str) -> bool {
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            Some('?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some('[') => {
                let Some(close) = p.iter().skip(2).position(|&c| c == ']').map(|i| i + 2) else {
                    return !n.is_empty() && n[0] == '[' && go(&p[1..], &n[1..]);
                };
                let Some(&c) = n.first() else { return false };
                let (negate, set) = match p[1] {
                    '!' | '^' => (true, &p[2..close]),
                    _ => (false, &p[1..close]),
                };
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        hit |= (set[i]..=set[i + 2]).contains(&c);
                        i += 3;
                    } else {
                        hit |= set[i] == c;
                        i += 1;
                    }
                }
                hit != negate && go(&p[close + 1..], &n[1..])
            }
            Some(&c) => n.first() == Some(&c) && go(&p[1..], &n[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    go(&p, &n)
}

/// An account for a login name the host does not know.
fn synthesize(name: &str) -> Account {
    let clean: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(32)
        .collect();
    let clean = if clean.is_empty() {
        "user".to_string()
    } else {
        clean
    };
    let uid = 1100 + clean.bytes().map(u32::from).sum::<u32>() % 800;
    Account {
        home: format!("/home/{clean}"),
        name: clean,
        uid,
        shell: "/bin/bash".into(),
        groups: Vec::new(),
    }
}

// ---------------------------------------------------------------- the Host

/// [`Host`] over a [`Shell`]: what a behavior drives.
pub struct ShellHost {
    sh: Shell,
}

impl ShellHost {
    fn reply(&mut self, output: Vec<u8>) -> HostReply {
        HostReply {
            output: String::from_utf8_lossy(&output).into_owned(),
            prompt: self.sh.prompt(),
            exit: self.sh.exit,
            tags: std::mem::take(&mut self.sh.tags),
        }
    }
}

impl Host for ShellHost {
    fn login(&mut self, user: &str) -> HostReply {
        self.sh.login(user);
        let banner = self.sh.login_banner();
        self.reply(banner.into_bytes())
    }

    fn run(&mut self, line: &str) -> HostReply {
        let out = self.sh.run_line(line);
        self.reply(out)
    }

    fn var(&self, name: &str) -> Option<String> {
        match name {
            "user" => Some(self.sh.user.name.clone()),
            "cwd" => Some(self.sh.cwd.clone()),
            "hostname" => Some(self.sh.spec.hostname.clone()),
            _ => None,
        }
    }
}

/// The emulated machine, shared by every protocol. Creates one independent
/// [`Host`] per session.
pub struct World {
    spec: Arc<HostSpec>,
    created_at: i64,
}

impl World {
    pub fn new(spec: HostSpec) -> World {
        World {
            spec: Arc::new(spec),
            created_at: system_clock()(),
        }
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<World> {
        Ok(World::new(HostSpec::load(path)?))
    }

    pub fn default_host() -> World {
        World::new(HostSpec::default_host())
    }

    pub fn spec(&self) -> &HostSpec {
        &self.spec
    }

    /// Like [`HostFactory::start`], with an explicit clock (for tests).
    pub fn start_with_clock(&self, clock: Clock) -> Box<dyn Host> {
        // The machine has been up as long as its spec says, plus however long
        // this honeypot process has been running, so uptime keeps advancing
        // across sessions instead of resetting to the same value each time.
        let since_start = u64::try_from((clock() - self.created_at).max(0)).unwrap_or(0);
        let uptime = self.spec.uptime_secs + since_start;
        Box::new(ShellHost {
            sh: Shell::new(self.spec.clone(), clock, uptime),
        })
    }
}

impl HostFactory for World {
    fn start(&self) -> Box<dyn Host> {
        self.start_with_clock(system_clock())
    }
}
