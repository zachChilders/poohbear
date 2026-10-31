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

    /// A failure with a one-line message on stderr.
    pub fn fail(status: i32, message: impl AsRef<str>) -> Streams {
        Streams {
            err: format!("{}\n", message.as_ref()).into_bytes(),
            status,
            ..Streams::default()
        }
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
        "cp" => files::cp(sh, args),
        "mv" => files::mv(sh, args),
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

/// Split `args` into single-letter flags, long flags and positionals.
/// A bare `--` ends flag parsing. Negative numbers (`-5`) are positionals.
pub(crate) fn split_flags(args: &[String]) -> (String, Vec<String>, Vec<String>) {
    let (mut short, mut long, mut rest) = (String::new(), Vec::new(), Vec::new());
    let mut flags_done = false;
    for a in args {
        if flags_done || a == "-" || !a.starts_with('-') {
            rest.push(a.clone());
        } else if a == "--" {
            flags_done = true;
        } else if let Some(l) = a.strip_prefix("--") {
            long.push(l.to_string());
        } else if a[1..].chars().all(|c| c.is_ascii_digit()) {
            rest.push(a.clone());
        } else {
            short.push_str(&a[1..]);
        }
    }
    (short, long, rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_splitting() {
        let (s, l, r) = split_flags(&v(&["-la", "--color=auto", "dir", "-", "-5", "--", "-x"]));
        assert_eq!(s, "la");
        assert_eq!(l, ["color=auto"]);
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
