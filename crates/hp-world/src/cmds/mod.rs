//! The commands the emulated shell knows.
//!
//! Grouped by concern: [`files`] (filesystem), [`info`] (system facts),
//! [`text`] (echo, printf, base64), [`net`] (wget/curl, simulated). Each
//! command is a plain function from arguments and stdin to [`Streams`].

mod files;
mod info;
mod net;
mod text;

use crate::shell::Shell;

/// What a command produced. `out` goes down the pipe (or to the terminal),
/// `err` always goes to the terminal.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Streams {
    pub out: Vec<u8>,
    pub err: Vec<u8>,
    pub status: i32,
}

impl Streams {
    pub fn out(bytes: impl Into<Vec<u8>>) -> Streams {
        Streams {
            out: bytes.into(),
            ..Streams::default()
        }
    }

    /// A command that failed with a single message.
    pub fn fail(status: i32, message: impl AsRef<str>) -> Streams {
        let mut s = Streams::default();
        s.error(status, message);
        s
    }

    /// Report a failure: the message (one line) goes to stderr and the
    /// command's exit status becomes `status`. The command carries on.
    pub fn error(&mut self, status: i32, message: impl AsRef<str>) {
        self.err.extend_from_slice(message.as_ref().as_bytes());
        self.err.push(b'\n');
        self.status = status;
    }
}

/// Commands that exist on a normal Linux box but that we do not emulate.
/// They succeed silently: "command not found" for `awk` or `find` would be a
/// far louder tell than an empty result.
const STUBS: &[&str] = &[
    "awk",
    "sed",
    "tar",
    "gzip",
    "gunzip",
    "zcat",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "python",
    "python3",
    "perl",
    "systemctl",
    "service",
    "netstat",
    "ss",
    "lscpu",
    "find",
    "xargs",
    "tee",
    "sort",
    "uniq",
    "cut",
    "tr",
    "dd",
    "ping",
    "apt",
    "apt-get",
    "dpkg",
    "ln",
    "chgrp",
    "ssh",
    "scp",
    "mount",
    "lsblk",
    "dmesg",
    "journalctl",
    "lsmod",
    "ulimit",
    "umask",
    "stty",
    "nice",
    "watch",
    "less",
    "more",
    "vi",
    "vim",
    "nano",
    "man",
    "file",
    "stat",
    "du",
    "id3",
    "alias",
    "set",
    "shopt",
    "trap",
    "wait",
    "disown",
    "bg",
    "fg",
    "jobs",
    "cron",
    "iptables",
    "ufw",
];

/// Commands implemented here, for `which`/`type`.
const IMPLEMENTED: &[&str] = &[
    "echo", "printf", "pwd", "ls", "cat", "touch", "mkdir", "rm", "cp", "mv", "chmod", "chown",
    "head", "tail", "wc", "grep", "whoami", "id", "groups", "uname", "hostname", "uptime", "date",
    "w", "who", "ps", "env", "printenv", "free", "df", "ip", "nproc", "which", "sleep", "true",
    "false", "sudo", "su", "crontab", "kill", "pkill", "killall", "nohup", "setsid", "time",
    "command", "base64", "wget", "curl", "sh", "bash", "clear", "history",
];

/// Is there an executable file by this name (as opposed to a builtin)?
pub(crate) fn is_executable(name: &str) -> bool {
    IMPLEMENTED.contains(&name) || STUBS.contains(&name)
}

/// Run `name` with `args`. Unknown commands behave like bash.
pub(crate) fn dispatch(sh: &mut Shell, name: &str, args: &[String], stdin: &[u8]) -> Streams {
    if name.contains('/') {
        return files::exec_path(sh, name);
    }
    match name {
        // text
        "echo" => text::echo(args),
        "printf" => text::printf(args),
        "base64" => text::base64(sh, args, stdin),
        // files
        "pwd" => Streams::out(format!("{}\n", sh.cwd)),
        "cd" => files::cd(sh, args),
        "ls" => files::ls(sh, args),
        "cat" => files::cat(sh, args, stdin),
        "touch" => files::touch(sh, args),
        "mkdir" => files::mkdir(sh, args),
        "rm" => files::rm(sh, args),
        "cp" => files::transfer(sh, args, false),
        "mv" => files::transfer(sh, args, true),
        "chmod" => files::chmod(sh, args),
        "chown" => files::chown(sh, args),
        "head" => files::head_tail(sh, args, stdin, true),
        "tail" => files::head_tail(sh, args, stdin, false),
        "wc" => files::wc(sh, args, stdin),
        "grep" => files::grep(sh, args, stdin),
        // system
        "whoami" => Streams::out(format!("{}\n", sh.user.name)),
        "id" => info::id(sh, args),
        "groups" => info::groups(sh),
        "uname" => info::uname(sh, args),
        "hostname" => info::hostname(sh, args),
        "uptime" => info::uptime(sh, args),
        "date" => info::date(sh, args),
        "w" => info::w(sh),
        "who" => info::who(sh),
        "ps" => info::ps(sh, args),
        "env" | "printenv" => info::env(sh, args),
        "export" => info::export(sh, args),
        "unset" => info::unset(sh, args),
        "history" => info::history(sh),
        "clear" => Streams::out("\x1b[H\x1b[2J\x1b[3J"),
        "free" => info::free(sh, args),
        "df" => info::df(args),
        "ip" => info::ip(sh, args),
        "nproc" => Streams::out(format!("{}\n", sh.spec.cpu.cores)),
        "which" => info::which(args),
        "sudo" => info::sudo(sh, args, stdin),
        "su" => info::su(sh, args),
        "crontab" => info::crontab(sh, args),
        "exit" | "logout" => {
            sh.exit = true;
            Streams::out("logout\n")
        }
        "sleep" | "true" | "kill" | "pkill" | "killall" | "umask" => Streams::default(),
        "false" => Streams {
            status: 1,
            ..Streams::default()
        },
        // wrappers that just run what follows
        "nohup" | "setsid" | "time" | "command" | "exec" => info::wrapper(sh, args, stdin),
        "sh" | "bash" => info::shell(sh, args, stdin),
        // network (simulated)
        "wget" => net::wget(sh, args),
        "curl" => net::curl(sh, args),
        _ if STUBS.contains(&name) => Streams::default(),
        _ => Streams::fail(127, format!("-bash: {name}: command not found")),
    }
}

/// A command line, split into flags, options with values, and operands.
#[derive(Debug, Default)]
pub(crate) struct Opts {
    /// Single-letter flags, in order (`-la` gives `la`).
    pub flags: String,
    /// Long flags without a value (`--force` gives `force`).
    pub long: Vec<String>,
    /// Options that took a value, by name: `-O file` and `--output-document=file`.
    pub values: Vec<(String, String)>,
    /// Everything else. A bare `--` ends option parsing; `-` and negative
    /// numbers (`-5`) are operands.
    pub rest: Vec<String>,
}

impl Opts {
    /// `short_values` lists the single-letter options that take an argument
    /// (attached or as the next word); `long_values` the long ones.
    pub fn parse(args: &[String], short_values: &str, long_values: &[&str]) -> Opts {
        let mut o = Opts::default();
        let mut it = args.iter();
        let mut options_done = false;
        while let Some(a) = it.next() {
            if options_done
                || a == "-"
                || !a.starts_with('-')
                || a[1..].chars().all(|c| c.is_ascii_digit())
            {
                o.rest.push(a.clone());
            } else if a == "--" {
                options_done = true;
            } else if let Some(long) = a.strip_prefix("--") {
                let (key, inline) = long
                    .split_once('=')
                    .map_or((long, None), |(k, v)| (k, Some(v.to_string())));
                if !long_values.contains(&key) {
                    o.long.push(key.to_string());
                } else if let Some(v) = inline.or_else(|| it.next().cloned()) {
                    o.values.push((key.to_string(), v));
                }
            } else {
                for (i, c) in a[1..].char_indices() {
                    if short_values.contains(c) {
                        let attached = &a[1 + i + c.len_utf8()..];
                        let v = if attached.is_empty() {
                            it.next().cloned()
                        } else {
                            Some(attached.to_string())
                        };
                        o.values.extend(v.map(|v| (c.to_string(), v)));
                        break;
                    }
                    o.flags.push(c);
                }
            }
        }
        o
    }

    /// Is the single-letter flag set?
    pub fn has(&self, c: char) -> bool {
        self.flags.contains(c)
    }

    /// Is the long flag set?
    pub fn is_set(&self, long: &str) -> bool {
        self.long.iter().any(|l| l == long)
    }

    /// The value given for any of `names` (the last one wins).
    pub fn value(&self, names: &[&str]) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| names.contains(&k.as_str()))
            .map(|(_, v)| v.as_str())
    }
}

/// `(flags, long flags, operands)` for commands with no value-taking options.
pub(crate) fn split_flags(args: &[String]) -> (String, Vec<String>, Vec<String>) {
    let o = Opts::parse(args, "", &[]);
    (o.flags, o.long, o.rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_with_values_attached_separate_and_long() {
        let o = Opts::parse(
            &v(&[
                "-qO-",
                "-P",
                "dir",
                "--output-document=x",
                "-t5",
                "url",
                "--",
                "-z",
            ]),
            "OPt",
            &["output-document"],
        );
        assert_eq!(o.flags, "q");
        assert_eq!(
            o.value(&["O", "output-document"]),
            Some("x"),
            "the last value wins"
        );
        assert_eq!(o.value(&["P"]), Some("dir"));
        assert_eq!(o.value(&["t"]), Some("5"));
        assert_eq!(o.rest, ["url", "-z"]);
        assert!(o.has('q') && !o.has('O'));
        let o = Opts::parse(&v(&["--force", "-O"]), "O", &[]);
        assert!(
            o.is_set("force") && o.values.is_empty(),
            "a value option at the very end has no value"
        );
    }

    #[test]
    fn flag_splitting() {
        let (s, l, r) = split_flags(&v(&["-la", "--color=auto", "dir", "-", "-5", "--", "-x"]));
        assert_eq!(s, "la");
        assert_eq!(l, ["color"]);
        assert_eq!(r, ["dir", "-", "-5", "-x"]);
    }

    #[test]
    fn executables_include_implemented_and_stubbed_commands_but_not_builtins() {
        for c in ["ls", "awk", "wget", "sudo"] {
            assert!(is_executable(c), "{c}");
        }
        assert!(!is_executable("cd"), "builtins are not files");
        assert!(!is_executable("definitely-not-a-command"));
    }

    #[test]
    fn streams_helpers() {
        assert_eq!(
            Streams::fail(2, "boom"),
            Streams {
                err: b"boom\n".to_vec(),
                status: 2,
                out: vec![]
            }
        );
        assert_eq!(Streams::out("x").out, b"x");
    }
}
