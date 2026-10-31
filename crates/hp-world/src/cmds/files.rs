//! Filesystem commands. Messages follow GNU coreutils 8.32 (Ubuntu 22.04):
//! most quote file names with straight quotes (`'x'`), `mkdir` with curly ones.

use regex::RegexBuilder;

use super::{split_flags, Streams};
use crate::fs::{split, FsError, Kind, Meta, Node};
use crate::shell::Shell;
use crate::timefmt::ls_date;

fn err(cmd: &str, what: &str, e: FsError) -> String {
    format!("{cmd}: {what}: {}\n", e.message())
}

// ---------------------------------------------------------------- running files

/// `./x` or `/tmp/x`: running a file. Nothing is executed. A file the peer
/// put there this session raises `payload_exec`, which is the point.
pub(crate) fn exec_path(sh: &mut Shell, name: &str) -> Streams {
    let abs = sh.abs(name);
    let Some(node) = sh.fs.node(&abs) else {
        return Streams::fail(127, format!("-bash: {name}: No such file or directory"));
    };
    if node.is_dir() {
        return Streams::fail(126, format!("-bash: {name}: Is a directory"));
    }
    let mode = node.meta.mode;
    let runnable = if sh.user.is_root() {
        mode & 0o111 != 0
    } else if node.meta.owner == sh.user.name {
        mode & 0o100 != 0
    } else {
        mode & 0o001 != 0
    };
    if !runnable || !sh.fs.can_traverse(&abs, sh.actor()) {
        return Streams::fail(126, format!("-bash: {name}: Permission denied"));
    }
    if sh.created.contains(&abs) {
        sh.tag("payload_exec");
    }
    Streams::default()
}

// ---------------------------------------------------------------------- cd / ls

pub(crate) fn cd(sh: &mut Shell, args: &[String]) -> Streams {
    let target = match args.first().map(String::as_str) {
        None | Some("~") => sh.user.home.clone(),
        Some("-") => sh
            .env
            .get("OLDPWD")
            .cloned()
            .unwrap_or_else(|| sh.cwd.clone()),
        Some(p) => p.to_string(),
    };
    let abs = sh.abs(&target);
    match sh.fs.node(&abs) {
        None => return Streams::fail(1, format!("-bash: cd: {target}: No such file or directory")),
        Some(n) if !n.is_dir() => {
            return Streams::fail(1, format!("-bash: cd: {target}: Not a directory"))
        }
        Some(_) => {}
    }
    if !sh.fs.can_traverse(&format!("{abs}/x"), sh.actor()) {
        return Streams::fail(1, format!("-bash: cd: {target}: Permission denied"));
    }
    let old = std::mem::replace(&mut sh.cwd, abs.clone());
    sh.env.insert("OLDPWD".into(), old);
    sh.env.insert("PWD".into(), abs);
    Streams::default()
}

struct Row {
    name: String,
    is_dir: bool,
    size: usize,
    meta: Meta,
    nlink: usize,
}

impl Row {
    fn new(name: &str, node: &Node) -> Row {
        let nlink = match &node.kind {
            Kind::Dir(children) => 2 + children.values().filter(|c| c.is_dir()).count(),
            Kind::File(_) => 1,
        };
        Row {
            name: name.into(),
            is_dir: node.is_dir(),
            size: node.size(),
            meta: node.meta.clone(),
            nlink,
        }
    }
}

fn mode_string(is_dir: bool, mode: u32) -> String {
    let mut s = String::from(if is_dir { "d" } else { "-" });
    for (shift, special, set, unset) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let bits = mode >> shift & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    s
}

fn human(size: usize) -> String {
    const UNITS: [&str; 4] = ["K", "M", "G", "T"];
    if size < 1024 {
        return size.to_string();
    }
    let mut v = size as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    // GNU rounds up and shows one decimal below 10.
    if v < 10.0 {
        format!("{:.1}{}", (v * 10.0).ceil() / 10.0, UNITS[u])
    } else {
        format!("{}{}", v.ceil() as u64, UNITS[u])
    }
}

/// Sort like `ls` in an en_US locale: ignore case and leading dots.
fn sort_key(name: &str) -> (String, String) {
    (
        name.trim_start_matches('.').to_lowercase(),
        name.to_string(),
    )
}

fn long_lines(rows: &[Row], now: i64, human_sizes: bool) -> Vec<String> {
    let size = |r: &Row| {
        if human_sizes {
            human(r.size)
        } else {
            r.size.to_string()
        }
    };
    let w = |f: &dyn Fn(&Row) -> String| rows.iter().map(|r| f(r).len()).max().unwrap_or(0);
    let (wn, wo, wg, ws) = (
        w(&|r| r.nlink.to_string()),
        w(&|r| r.meta.owner.clone()),
        w(&|r| r.meta.group.clone()),
        w(&size),
    );
    rows.iter()
        .map(|r| {
            format!(
                "{} {:>wn$} {:<wo$} {:<wg$} {:>ws$} {} {}",
                mode_string(r.is_dir, r.meta.mode),
                r.nlink,
                r.meta.owner,
                r.meta.group,
                size(r),
                ls_date(r.meta.mtime, now),
                r.name,
            )
        })
        .collect()
}

/// Terminal-width (80) column layout, filled down then across, like `ls`.
fn columns(names: &[String]) -> String {
    if names.is_empty() {
        return String::new();
    }
    let width = 80;
    let total: usize =
        names.iter().map(|n| n.chars().count()).sum::<usize>() + 2 * (names.len() - 1);
    if total <= width {
        return names.join("  ") + "\n";
    }
    let col_width = names.iter().map(|n| n.chars().count()).max().unwrap_or(0) + 2;
    let per_line = (width / col_width).max(1);
    let rows = names.len().div_ceil(per_line);
    let mut out = String::new();
    for r in 0..rows {
        let line: Vec<String> = (0..per_line)
            .filter_map(|c| names.get(c * rows + r))
            .enumerate()
            .map(|(i, n)| {
                let is_last = names.get((i + 1) * rows + r).is_none();
                if is_last {
                    n.clone()
                } else {
                    format!("{n:<col_width$}")
                }
            })
            .collect();
        out.push_str(line.join("").trim_end());
        out.push('\n');
    }
    out
}

pub(crate) fn ls(sh: &mut Shell, args: &[String]) -> Streams {
    let (flags, _, paths) = split_flags(args);
    let all = flags.contains('a');
    let almost = flags.contains('A');
    let long = flags.contains('l');
    let human_sizes = flags.contains('h');
    let dir_only = flags.contains('d');
    let now = sh.now();
    let paths = if paths.is_empty() {
        vec![".".to_string()]
    } else {
        paths
    };

    let (mut out, mut errs, mut status) = (String::new(), String::new(), 0);
    let mut files: Vec<Row> = Vec::new();
    let mut dirs: Vec<(String, String)> = Vec::new();

    for p in &paths {
        let abs = sh.abs(p);
        // Checked first: a directory you cannot search must not reveal whether
        // anything exists in it.
        if !sh.fs.can_traverse(&abs, sh.actor()) {
            errs.push_str(&format!("ls: cannot access '{p}': Permission denied\n"));
            status = 2;
            continue;
        }
        match sh.fs.node(&abs) {
            None => {
                errs.push_str(&format!(
                    "ls: cannot access '{p}': No such file or directory\n"
                ));
                status = 2;
            }
            Some(n) if n.is_dir() && !dir_only => dirs.push((p.clone(), abs)),
            Some(n) => files.push(Row::new(p, n)),
        }
    }

    let render = |rows: Vec<Row>| -> String {
        if long {
            long_lines(&rows, now, human_sizes).join("\n") + if rows.is_empty() { "" } else { "\n" }
        } else {
            columns(&rows.into_iter().map(|r| r.name).collect::<Vec<_>>())
        }
    };

    files.sort_by_key(|r| sort_key(&r.name));
    out.push_str(&render(files));

    let show_headers = paths.len() > 1;
    for (i, (label, abs)) in dirs.iter().enumerate() {
        if !sh.fs.can_read(abs, sh.actor()) {
            errs.push_str(&format!(
                "ls: cannot open directory '{label}': Permission denied\n"
            ));
            status = 2;
            continue;
        }
        if show_headers {
            if !out.is_empty() || i > 0 {
                out.push('\n');
            }
            out.push_str(&format!("{label}:\n"));
        }
        let mut rows: Vec<Row> = sh
            .fs
            .list(abs)
            .unwrap_or_default()
            .into_iter()
            .filter(|(name, _)| all || almost || !name.starts_with('.'))
            .map(|(name, node)| Row::new(name, node))
            .collect();
        if all {
            let parent = split(abs).map_or("/", |(p, _)| p);
            if let Some(n) = sh.fs.node(abs) {
                rows.push(Row::new(".", n));
            }
            if let Some(n) = sh.fs.node(parent) {
                rows.push(Row::new("..", n));
            }
        }
        rows.sort_by_key(|r| sort_key(&r.name));
        if long {
            let blocks: usize = rows
                .iter()
                .map(|r| {
                    if r.is_dir {
                        4
                    } else {
                        r.size.div_ceil(4096) * 4
                    }
                })
                .sum();
            out.push_str(&format!("total {blocks}\n"));
        }
        out.push_str(&render(rows));
    }
    Streams {
        out: out.into_bytes(),
        err: errs.into_bytes(),
        status,
    }
}

// ------------------------------------------------------------------ reading files

fn is_sensitive(abs: &str) -> bool {
    abs == "/etc/shadow" || abs.contains("/.ssh/id_") || abs.ends_with("/.bash_history")
}

/// Read a file for a command. Reading anything sensitive is flagged whether
/// or not it is allowed: the attempt is what matters.
fn read_file(sh: &mut Shell, name: &str) -> Result<Vec<u8>, FsError> {
    let abs = sh.abs(name);
    if is_sensitive(&abs) {
        sh.tag("credential_access");
    }
    // A directory you cannot search must not reveal whether anything exists in it.
    if !sh.fs.can_traverse(&abs, sh.actor()) {
        return Err(FsError::Denied);
    }
    match sh.fs.node(&abs) {
        None => return Err(FsError::NotFound),
        Some(n) if n.is_dir() => return Err(FsError::IsADirectory),
        Some(_) => {}
    }
    if !sh.fs.can_read(&abs, sh.actor()) {
        return Err(FsError::Denied);
    }
    sh.fs.read(&abs).map(<[u8]>::to_vec)
}

/// `cmd: name: reason`, the common coreutils shape.
fn read_for(sh: &mut Shell, cmd: &str, name: &str) -> Result<Vec<u8>, String> {
    read_file(sh, name).map_err(|e| err(cmd, name, e))
}

pub(crate) fn cat(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (flags, _, files) = split_flags(args);
    let number = flags.contains('n');
    let mut out = Vec::new();
    let mut errs = String::new();
    let mut status = 0;
    let inputs: Vec<&str> = if files.is_empty() {
        vec!["-"]
    } else {
        files.iter().map(String::as_str).collect()
    };
    for f in inputs {
        let data = if f == "-" {
            stdin.to_vec()
        } else {
            match read_for(sh, "cat", f) {
                Ok(d) => d,
                Err(e) => {
                    errs.push_str(&e);
                    status = 1;
                    continue;
                }
            }
        };
        out.extend(data);
    }
    if number {
        let text = String::from_utf8_lossy(&out).into_owned();
        out = text
            .lines()
            .enumerate()
            .map(|(i, l)| format!("{:>6}\t{l}\n", i + 1))
            .collect::<String>()
            .into_bytes();
    }
    Streams {
        out,
        err: errs.into_bytes(),
        status,
    }
}

pub(crate) fn head_tail(sh: &mut Shell, args: &[String], stdin: &[u8], head: bool) -> Streams {
    let cmd = if head { "head" } else { "tail" };
    let (mut count, mut files) = (10usize, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-n" {
            count = it
                .next()
                .and_then(|v| v.trim_start_matches('+').parse().ok())
                .unwrap_or(10);
        } else if let Some(n) = a.strip_prefix("-n") {
            count = n.parse().unwrap_or(10);
        } else if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| c.is_ascii_digit()) {
            count = a[1..].parse().unwrap_or(10);
        } else if a.starts_with('-') && a.len() > 1 {
            // -f, -q, ...: nothing to follow or silence here
        } else {
            files.push(a.clone());
        }
    }
    let (mut out, mut errs, mut status) = (Vec::new(), String::new(), 0);
    let inputs: Vec<String> = if files.is_empty() {
        vec!["-".into()]
    } else {
        files.clone()
    };
    for (i, f) in inputs.iter().enumerate() {
        let data = if f == "-" {
            stdin.to_vec()
        } else {
            match read_file(sh, f) {
                Ok(d) => d,
                Err(e) => {
                    errs.push_str(&format!(
                        "{cmd}: cannot open '{f}' for reading: {}\n",
                        e.message()
                    ));
                    status = 1;
                    continue;
                }
            }
        };
        if inputs.len() > 1 {
            out.extend(format!("{}==> {f} <==\n", if i > 0 { "\n" } else { "" }).into_bytes());
        }
        let text = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let picked: Vec<&str> = if head {
            lines.into_iter().take(count).collect()
        } else {
            let skip = lines.len().saturating_sub(count);
            lines.into_iter().skip(skip).collect()
        };
        out.extend(picked.concat().into_bytes());
    }
    Streams {
        out,
        err: errs.into_bytes(),
        status,
    }
}

pub(crate) fn wc(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (flags, _, files) = split_flags(args);
    let (l, w, c) = (
        flags.contains('l'),
        flags.contains('w'),
        flags.contains('c') || flags.contains('m'),
    );
    let all = !(l || w || c);
    let fmt = |data: &[u8], label: Option<&str>| {
        let text = String::from_utf8_lossy(data);
        let mut fields = Vec::new();
        if l || all {
            fields.push(data.iter().filter(|b| **b == b'\n').count());
        }
        if w || all {
            fields.push(text.split_whitespace().count());
        }
        if c || all {
            fields.push(data.len());
        }
        let width = if fields.len() > 1 || label.is_some() {
            7
        } else {
            0
        };
        let mut line = fields
            .iter()
            .map(|n| format!("{n:>width$}"))
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(l) = label {
            line.push(' ');
            line.push_str(l);
        }
        line + "\n"
    };
    if files.is_empty() {
        return Streams::out(fmt(stdin, None));
    }
    let (mut out, mut errs, mut status) = (String::new(), String::new(), 0);
    for f in &files {
        match read_for(sh, "wc", f) {
            Ok(d) => out.push_str(&fmt(&d, Some(f))),
            Err(e) => {
                errs.push_str(&e);
                status = 1;
            }
        }
    }
    Streams {
        out: out.into_bytes(),
        err: errs.into_bytes(),
        status,
    }
}

pub(crate) fn grep(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let mut flags = String::new();
    let (mut patterns, mut rest): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-e" {
            patterns.extend(it.next().cloned());
        } else if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") {
            flags.push_str(&a[1..]);
        } else if !a.starts_with("--") {
            rest.push(a.clone());
        }
    }
    if patterns.is_empty() {
        if rest.is_empty() {
            return Streams::fail(2, "Usage: grep [OPTION]... PATTERNS [FILE]...");
        }
        patterns.push(rest.remove(0));
    }
    let has = |c| flags.contains(c);
    let body = patterns
        .iter()
        .map(|p| {
            if has('F') {
                regex::escape(p)
            } else {
                p.clone()
            }
        })
        .collect::<Vec<_>>()
        .join("|");
    let body = if has('w') {
        format!(r"\b(?:{body})\b")
    } else {
        body
    };
    let re = match RegexBuilder::new(&body)
        .case_insensitive(has('i'))
        .size_limit(1 << 20)
        .build()
    {
        Ok(r) => r,
        Err(_) => return Streams::fail(2, "grep: Invalid regular expression"),
    };

    let inputs: Vec<String> = if rest.is_empty() {
        vec!["-".into()]
    } else {
        rest.clone()
    };
    let prefix = inputs.len() > 1 && !has('h');
    let (mut out, mut errs, mut matched, mut status) = (String::new(), String::new(), false, 0);
    for f in &inputs {
        let data = if f == "-" {
            stdin.to_vec()
        } else {
            match read_for(sh, "grep", f) {
                Ok(d) => d,
                Err(e) => {
                    errs.push_str(&e);
                    status = 2;
                    continue;
                }
            }
        };
        let text = String::from_utf8_lossy(&data);
        let mut count = 0;
        for (n, line) in text.lines().enumerate() {
            if re.is_match(line) == has('v') {
                continue;
            }
            count += 1;
            matched = true;
            if has('c') || has('q') {
                continue;
            }
            let label = if prefix {
                format!("{f}:")
            } else {
                String::new()
            };
            let num = if has('n') {
                format!("{}:", n + 1)
            } else {
                String::new()
            };
            if has('o') {
                for m in re.find_iter(line) {
                    out.push_str(&format!("{label}{num}{}\n", m.as_str()));
                }
            } else {
                out.push_str(&format!("{label}{num}{line}\n"));
            }
        }
        if has('c') && !has('q') {
            out.push_str(&format!(
                "{}{count}\n",
                if prefix {
                    format!("{f}:")
                } else {
                    String::new()
                }
            ));
        }
    }
    if status == 0 && !matched {
        status = 1;
    }
    if has('q') && matched {
        return Streams::default();
    }
    Streams {
        out: out.into_bytes(),
        err: errs.into_bytes(),
        status,
    }
}

// ------------------------------------------------------------------ changing files

pub(crate) fn touch(sh: &mut Shell, args: &[String]) -> Streams {
    let (_, _, files) = split_flags(args);
    if files.is_empty() {
        return Streams::fail(
            1,
            "touch: missing file operand\nTry 'touch --help' for more information.",
        );
    }
    let (mut errs, mut status) = (String::new(), 0);
    for f in &files {
        let abs = sh.abs(f);
        let result = if sh.fs.exists(&abs) {
            if sh.fs.can_write(&abs, sh.actor()) {
                let now = sh.now();
                sh.fs.set_mtime(&abs, now)
            } else {
                Err(FsError::Denied)
            }
        } else {
            sh.write_file(&abs, b"", true)
        };
        if let Err(e) = result {
            errs.push_str(&format!("touch: cannot touch '{f}': {}\n", e.message()));
            status = 1;
        }
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}

pub(crate) fn mkdir(sh: &mut Shell, args: &[String]) -> Streams {
    let (flags, longs, dirs) = split_flags(args);
    let parents = flags.contains('p') || longs.iter().any(|l| l == "parents");
    if dirs.is_empty() {
        return Streams::fail(
            1,
            "mkdir: missing operand\nTry 'mkdir --help' for more information.",
        );
    }
    let (mut errs, mut status) = (String::new(), 0);
    for d in &dirs {
        let abs = sh.abs(d);
        let mut path = String::new();
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        for (i, c) in comps.iter().enumerate() {
            path.push('/');
            path.push_str(c);
            let last = i + 1 == comps.len();
            if sh.fs.is_dir(&path) {
                if last && !parents {
                    errs.push_str(&format!(
                        "mkdir: cannot create directory ‘{d}’: File exists\n"
                    ));
                    status = 1;
                }
                continue;
            }
            let result = if sh.fs.exists(&path) {
                Err(FsError::Exists)
            } else if !last && !parents {
                Err(FsError::NotFound)
            } else if !sh.fs.can_write(&path, sh.actor()) {
                Err(FsError::Denied)
            } else {
                let meta = sh.new_meta(0o755);
                sh.fs.mkdir(&path, meta)
            };
            if let Err(e) = result {
                errs.push_str(&format!(
                    "mkdir: cannot create directory ‘{d}’: {}\n",
                    e.message()
                ));
                status = 1;
                break;
            }
        }
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}

pub(crate) fn rm(sh: &mut Shell, args: &[String]) -> Streams {
    let (flags, longs, paths) = split_flags(args);
    let recursive =
        flags.contains('r') || flags.contains('R') || longs.iter().any(|l| l == "recursive");
    let force = flags.contains('f') || longs.iter().any(|l| l == "force");
    let no_preserve = longs.iter().any(|l| l == "no-preserve-root");
    if paths.is_empty() {
        return if force {
            Streams::default()
        } else {
            Streams::fail(
                1,
                "rm: missing operand\nTry 'rm --help' for more information.",
            )
        };
    }
    let (mut errs, mut status) = (String::new(), 0);
    for p in &paths {
        let abs = sh.abs(p);
        let top_level = abs.matches('/').count() == 1;
        if recursive && (abs == "/" || (top_level && abs != "/tmp")) {
            sh.tag("destructive_command");
        }
        if abs == "/" {
            if !recursive {
                errs.push_str("rm: cannot remove '/': Is a directory\n");
            } else if !no_preserve {
                errs.push_str("rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe\n");
            } else if sh.user.is_root() {
                let names: Vec<String> = sh
                    .fs
                    .list("/")
                    .unwrap_or_default()
                    .iter()
                    .map(|(n, _)| format!("/{n}"))
                    .collect();
                for n in names {
                    let _ = sh.fs.remove(&n, true);
                }
                continue;
            } else {
                errs.push_str("rm: cannot remove '/': Permission denied\n");
            }
            status = 1;
            continue;
        }
        let Some(node) = sh.fs.node(&abs) else {
            if !force {
                errs.push_str(&format!(
                    "rm: cannot remove '{p}': No such file or directory\n"
                ));
                status = 1;
            }
            continue;
        };
        let is_dir = node.is_dir();
        let result = if is_dir && !recursive {
            Err(FsError::IsADirectory)
        } else if !sh.fs.can_write(&abs, sh.actor()) {
            Err(FsError::Denied)
        } else {
            sh.fs.remove(&abs, recursive)
        };
        if let Err(e) = result {
            if !(force && e == FsError::NotFound) {
                errs.push_str(&format!("rm: cannot remove '{p}': {}\n", e.message()));
                status = 1;
            }
        } else {
            sh.created.remove(&abs);
        }
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}

/// Resolve the destination of `cp`/`mv`: into the directory if it is one.
fn destination(sh: &Shell, src: &str, dst: &str) -> String {
    let abs = sh.abs(dst);
    if sh.fs.is_dir(&abs) {
        let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or(src);
        format!("{}/{name}", abs.trim_end_matches('/'))
    } else {
        abs
    }
}

enum Xfer {
    /// The source does not exist.
    NoSource,
    /// `cp` of a directory without `-r`.
    OmitDir,
    /// Anything wrong with the destination or permissions.
    Fs(FsError),
}

fn move_or_copy(
    sh: &mut Shell,
    from: &str,
    to: &str,
    moving: bool,
    recursive: bool,
) -> Result<(), Xfer> {
    let node = sh.fs.node(from).ok_or(Xfer::NoSource)?;
    if node.is_dir() && !recursive && !moving {
        return Err(Xfer::OmitDir);
    }
    sh.fs.parent_ok(to).map_err(Xfer::Fs)?;
    let denied = !sh.fs.can_read(from, sh.actor())
        || !sh.fs.can_write(to, sh.actor())
        || (moving && !sh.fs.can_write(from, sh.actor()));
    if denied {
        return Err(Xfer::Fs(FsError::Denied));
    }
    let done = if moving {
        sh.fs.rename(from, to)
    } else {
        sh.fs.copy(from, to)
    };
    done.map_err(Xfer::Fs)
}

fn transfer(sh: &mut Shell, args: &[String], moving: bool) -> Streams {
    let cmd = if moving { "mv" } else { "cp" };
    let (flags, longs, paths) = split_flags(args);
    let recursive = flags.contains('r')
        || flags.contains('R')
        || flags.contains('a')
        || longs.iter().any(|l| l == "recursive");
    if paths.len() < 2 {
        let msg = if paths.is_empty() {
            format!("{cmd}: missing file operand")
        } else {
            format!(
                "{cmd}: missing destination file operand after '{}'",
                paths[0]
            )
        };
        return Streams::fail(
            1,
            format!("{msg}\nTry '{cmd} --help' for more information."),
        );
    }
    let (srcs, dst) = paths.split_at(paths.len() - 1);
    let dst = &dst[0];
    if srcs.len() > 1 && !sh.fs.is_dir(&sh.abs(dst)) {
        return Streams::fail(1, format!("{cmd}: target '{dst}' is not a directory"));
    }
    let (mut errs, mut status) = (String::new(), 0);
    for s in srcs {
        let from = sh.abs(s);
        let to = destination(sh, s, dst);
        let result = move_or_copy(sh, &from, &to, moving, recursive);
        match result {
            Ok(()) => {
                let (user, now) = (sh.user.name.clone(), sh.now());
                if moving {
                    if sh.created.remove(&from) {
                        sh.created.insert(to.clone());
                    }
                } else {
                    let _ = sh.fs.set_owner(&to, &user, &user);
                    let _ = sh.fs.set_mtime(&to, now);
                    sh.created.insert(to.clone());
                }
                sh.note_write(&to);
            }
            Err(Xfer::OmitDir) => {
                errs.push_str(&format!("cp: -r not specified; omitting directory '{s}'\n"));
                status = 1;
            }
            Err(Xfer::NoSource) => {
                errs.push_str(&format!(
                    "{cmd}: cannot stat '{s}': No such file or directory\n"
                ));
                status = 1;
            }
            Err(Xfer::Fs(e)) => {
                // GNU cp names only the destination; mv names both.
                let what = if moving {
                    format!("cannot move '{s}' to '{dst}'")
                } else {
                    format!("cannot create regular file '{dst}'")
                };
                errs.push_str(&format!("{cmd}: {what}: {}\n", e.message()));
                status = 1;
            }
        }
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}

pub(crate) fn cp(sh: &mut Shell, args: &[String]) -> Streams {
    transfer(sh, args, false)
}

pub(crate) fn mv(sh: &mut Shell, args: &[String]) -> Streams {
    transfer(sh, args, true)
}

/// Apply a `chmod` mode (octal like `755`, or symbolic like `u+x`, `a-w`,
/// `+x`, `go=r`) to `old`.
fn apply_mode(spec: &str, old: u32) -> Option<u32> {
    if let Ok(m) = u32::from_str_radix(spec, 8) {
        return (spec.len() <= 4).then_some(m);
    }
    let mut mode = old;
    for clause in spec.split(',') {
        let op_at = clause.find(['+', '-', '='])?;
        let (who, rest) = clause.split_at(op_at);
        let op = rest.chars().next()?;
        let perms = &rest[1..];
        let who = if who.is_empty() { "a" } else { who };
        let mut bits = 0u32;
        for p in perms.chars() {
            bits |= match p {
                'r' => 4,
                'w' => 2,
                'x' | 'X' => 1,
                's' | 't' => 0,
                _ => return None,
            };
        }
        for w in who.chars() {
            let shifts: &[u32] = match w {
                'u' => &[6],
                'g' => &[3],
                'o' => &[0],
                'a' => &[6, 3, 0],
                _ => return None,
            };
            for &s in shifts {
                match op {
                    '+' => mode |= bits << s,
                    '-' => mode &= !(bits << s),
                    _ => mode = (mode & !(7 << s)) | (bits << s),
                }
            }
        }
    }
    Some(mode)
}

pub(crate) fn chmod(sh: &mut Shell, args: &[String]) -> Streams {
    let (_, _, rest) = split_flags(args);
    let Some((spec, files)) = rest.split_first() else {
        return Streams::fail(
            1,
            "chmod: missing operand\nTry 'chmod --help' for more information.",
        );
    };
    if files.is_empty() {
        return Streams::fail(
            1,
            format!(
                "chmod: missing operand after '{spec}'\nTry 'chmod --help' for more information."
            ),
        );
    }
    let (mut errs, mut status) = (String::new(), 0);
    for f in files {
        let abs = sh.abs(f);
        let Some(node) = sh.fs.node(&abs) else {
            errs.push_str(&format!(
                "chmod: cannot access '{f}': No such file or directory\n"
            ));
            status = 1;
            continue;
        };
        let (old, owner) = (node.meta.mode, node.meta.owner.clone());
        let Some(new) = apply_mode(spec, old & 0o777) else {
            return Streams::fail(
                1,
                format!("chmod: invalid mode: ‘{spec}’\nTry 'chmod --help' for more information."),
            );
        };
        if !sh.user.is_root() && owner != sh.user.name {
            errs.push_str(&format!(
                "chmod: changing permissions of '{f}': Operation not permitted\n"
            ));
            status = 1;
            continue;
        }
        let _ = sh.fs.set_mode(&abs, (old & !0o777) | new);
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}

pub(crate) fn chown(sh: &mut Shell, args: &[String]) -> Streams {
    let (_, _, rest) = split_flags(args);
    let Some((owner, files)) = rest.split_first() else {
        return Streams::fail(
            1,
            "chown: missing operand\nTry 'chown --help' for more information.",
        );
    };
    let (user, group) = owner
        .split_once([':', '.'])
        .map_or((owner.as_str(), None), |(u, g)| (u, Some(g)));
    let mut errs = String::new();
    let mut status = 0;
    for f in files {
        let abs = sh.abs(f);
        if !sh.fs.exists(&abs) {
            errs.push_str(&format!(
                "chown: cannot access '{f}': No such file or directory\n"
            ));
            status = 1;
        } else if !sh.user.is_root() {
            errs.push_str(&format!(
                "chown: changing ownership of '{f}': Operation not permitted\n"
            ));
            status = 1;
        } else {
            let user = if user.is_empty() {
                sh.fs
                    .node(&abs)
                    .map(|n| n.meta.owner.clone())
                    .unwrap_or_default()
            } else {
                user.to_string()
            };
            let group = group.map_or_else(
                || {
                    sh.fs
                        .node(&abs)
                        .map(|n| n.meta.group.clone())
                        .unwrap_or_default()
                },
                str::to_string,
            );
            let _ = sh.fs.set_owner(&abs, &user, &group);
        }
    }
    Streams {
        err: errs.into_bytes(),
        status,
        ..Streams::default()
    }
}
