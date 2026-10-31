//! Filesystem commands. Messages follow GNU coreutils 8.32 (Ubuntu 22.04):
//! most quote file names with straight quotes (`'x'`), `mkdir` with curly ones.

use regex::RegexBuilder;

use super::{split_flags, Streams};
use crate::fs::{split, FsError, Kind, Meta, Node};
use crate::shell::Shell;
use crate::timefmt::ls_date;

/// `cmd: name: reason`, the common coreutils shape.
fn err(cmd: &str, what: &str, e: FsError) -> String {
    format!("{cmd}: {what}: {}", e.message())
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
    let has = |c| flags.contains(c);
    let (all, long) = (has('a'), has('l'));
    let now = sh.now();
    let paths = if paths.is_empty() {
        vec![".".to_string()]
    } else {
        paths
    };

    let mut r = Streams::default();
    let mut out = String::new();
    let mut files: Vec<Row> = Vec::new();
    let mut dirs: Vec<(String, String)> = Vec::new();
    for p in &paths {
        let abs = sh.abs(p);
        // Checked first: a directory you cannot search must not reveal whether
        // anything exists in it.
        if !sh.fs.can_traverse(&abs, sh.actor()) {
            r.error(2, format!("ls: cannot access '{p}': Permission denied"));
            continue;
        }
        match sh.fs.node(&abs) {
            None => r.error(
                2,
                format!("ls: cannot access '{p}': No such file or directory"),
            ),
            Some(n) if n.is_dir() && !has('d') => dirs.push((p.clone(), abs)),
            Some(n) => files.push(Row::new(p, n)),
        }
    }

    let render = |rows: Vec<Row>| -> String {
        if long {
            let lines = long_lines(&rows, now, has('h'));
            lines.iter().map(|l| format!("{l}\n")).collect()
        } else {
            columns(&rows.into_iter().map(|r| r.name).collect::<Vec<_>>())
        }
    };

    files.sort_by_key(|r| sort_key(&r.name));
    out.push_str(&render(files));

    for (i, (label, abs)) in dirs.iter().enumerate() {
        if !sh.fs.can_read(abs, sh.actor()) {
            r.error(
                2,
                format!("ls: cannot open directory '{label}': Permission denied"),
            );
            continue;
        }
        if paths.len() > 1 {
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
            .filter(|(name, _)| all || has('A') || !name.starts_with('.'))
            .map(|(name, node)| Row::new(name, node))
            .collect();
        if all {
            let parent = split(abs).map_or("/", |(p, _)| p);
            rows.extend(sh.fs.node(abs).map(|n| Row::new(".", n)));
            rows.extend(sh.fs.node(parent).map(|n| Row::new("..", n)));
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
    r.out = out.into_bytes();
    r
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

/// The inputs of a command like `cat`: each named file (`-` or no names means
/// stdin) with its contents. A file that cannot be read is reported on `r`
/// with exit status `status`, using `fail` for the wording, and skipped.
fn inputs(
    sh: &mut Shell,
    files: &[String],
    stdin: &[u8],
    r: &mut Streams,
    status: i32,
    fail: impl Fn(&str, FsError) -> String,
) -> Vec<(String, Vec<u8>)> {
    if files.is_empty() {
        return vec![("-".into(), stdin.to_vec())];
    }
    let mut found = Vec::new();
    for f in files {
        let data = if f == "-" {
            Ok(stdin.to_vec())
        } else {
            read_file(sh, f)
        };
        match data {
            Ok(d) => found.push((f.clone(), d)),
            Err(e) => r.error(status, fail(f, e)),
        }
    }
    found
}

pub(crate) fn cat(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (flags, _, files) = split_flags(args);
    let mut r = Streams::default();
    for (_, data) in inputs(sh, &files, stdin, &mut r, 1, |n, e| err("cat", n, e)) {
        r.out.extend(data);
    }
    if flags.contains('n') {
        let text = String::from_utf8_lossy(&r.out).into_owned();
        let numbered = text
            .lines()
            .enumerate()
            .map(|(i, l)| format!("{:>6}\t{l}\n", i + 1));
        r.out = numbered.collect::<String>().into_bytes();
    }
    r
}

pub(crate) fn head_tail(sh: &mut Shell, args: &[String], stdin: &[u8], head: bool) -> Streams {
    let cmd = if head { "head" } else { "tail" };
    let (mut count, mut files) = (10usize, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
        if a == "-n" {
            count = it
                .next()
                .and_then(|v| v.trim_start_matches('+').parse().ok())
                .unwrap_or(10);
        } else if let Some(n) = a.strip_prefix("-n") {
            count = n.parse().unwrap_or(10);
        } else if digits(a.trim_start_matches('-')) && a.starts_with('-') {
            count = a[1..].parse().unwrap_or(10);
        } else if !a.starts_with('-') || a == "-" {
            files.push(a.clone());
        } // other flags (-f, -q) have nothing to follow or silence here
    }
    let mut r = Streams::default();
    let found = inputs(sh, &files, stdin, &mut r, 1, |n, e| {
        format!("{cmd}: cannot open '{n}' for reading: {}", e.message())
    });
    for (i, (name, data)) in found.iter().enumerate() {
        if files.len() > 1 {
            r.out
                .extend(format!("{}==> {name} <==\n", if i > 0 { "\n" } else { "" }).bytes());
        }
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let skip = if head {
            0
        } else {
            lines.len().saturating_sub(count)
        };
        let take = if head { count } else { usize::MAX };
        r.out.extend(
            lines
                .into_iter()
                .skip(skip)
                .take(take)
                .collect::<String>()
                .bytes(),
        );
    }
    r
}

pub(crate) fn wc(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (flags, _, files) = split_flags(args);
    let (l, w, c) = (
        flags.contains('l'),
        flags.contains('w'),
        flags.contains('c') || flags.contains('m'),
    );
    let all = !(l || w || c);
    let mut r = Streams::default();
    for (name, data) in inputs(sh, &files, stdin, &mut r, 1, |n, e| err("wc", n, e)) {
        let mut fields = Vec::new();
        if l || all {
            fields.push(data.iter().filter(|b| **b == b'\n').count());
        }
        if w || all {
            fields.push(String::from_utf8_lossy(&data).split_whitespace().count());
        }
        if c || all {
            fields.push(data.len());
        }
        // GNU pads counts to a fixed width unless it is a lone number from stdin.
        let width = if fields.len() > 1 || !files.is_empty() {
            7
        } else {
            0
        };
        let mut line = fields
            .iter()
            .map(|n| format!("{n:>width$}"))
            .collect::<Vec<_>>()
            .join(" ");
        if !files.is_empty() {
            line = format!("{line} {name}");
        }
        r.out.extend(format!("{line}\n").bytes());
    }
    r
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
    let alternatives = patterns.iter().map(|p| {
        if has('F') {
            regex::escape(p)
        } else {
            p.clone()
        }
    });
    let body = alternatives.collect::<Vec<_>>().join("|");
    let body = if has('w') {
        format!(r"\b(?:{body})\b")
    } else {
        body
    };
    let Ok(re) = RegexBuilder::new(&body)
        .case_insensitive(has('i'))
        .size_limit(1 << 20)
        .build()
    else {
        return Streams::fail(2, "grep: Invalid regular expression");
    };

    let mut r = Streams::default();
    let prefix = rest.len() > 1 && !has('h');
    let mut matched = false;
    for (name, data) in inputs(sh, &rest, stdin, &mut r, 2, |n, e| err("grep", n, e)) {
        let label = if prefix {
            format!("{name}:")
        } else {
            String::new()
        };
        let mut count = 0;
        for (n, line) in String::from_utf8_lossy(&data).lines().enumerate() {
            if re.is_match(line) == has('v') {
                continue;
            }
            count += 1;
            if has('c') || has('q') {
                continue;
            }
            let num = if has('n') {
                format!("{}:", n + 1)
            } else {
                String::new()
            };
            let shown: Vec<&str> = if has('o') {
                re.find_iter(line).map(|m| m.as_str()).collect()
            } else {
                vec![line]
            };
            for text in shown {
                r.out.extend(format!("{label}{num}{text}\n").bytes());
            }
        }
        matched |= count > 0;
        if has('c') && !has('q') {
            r.out.extend(format!("{label}{count}\n").bytes());
        }
    }
    if has('q') && matched {
        return Streams::default();
    }
    if r.status == 0 && !matched {
        r.status = 1;
    }
    r
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
    let mut r = Streams::default();
    for f in &files {
        let abs = sh.abs(f);
        let result = if !sh.fs.exists(&abs) {
            sh.write_file(&abs, b"", true)
        } else if sh.fs.can_write(&abs, sh.actor()) {
            let now = sh.now();
            sh.fs.set_mtime(&abs, now)
        } else {
            Err(FsError::Denied)
        };
        if let Err(e) = result {
            r.error(1, format!("touch: cannot touch '{f}': {}", e.message()));
        }
    }
    r
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
    let mut r = Streams::default();
    for d in &dirs {
        let abs = sh.abs(d);
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        let mut path = String::new();
        for (i, c) in comps.iter().enumerate() {
            path.push('/');
            path.push_str(c);
            let last = i + 1 == comps.len();
            let result = if sh.fs.is_dir(&path) {
                if last && !parents {
                    Err(FsError::Exists)
                } else {
                    continue;
                }
            } else if sh.fs.exists(&path) {
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
                r.error(
                    1,
                    format!("mkdir: cannot create directory ‘{d}’: {}", e.message()),
                );
                break;
            }
        }
    }
    r
}

pub(crate) fn rm(sh: &mut Shell, args: &[String]) -> Streams {
    let (flags, longs, paths) = split_flags(args);
    let recursive =
        flags.contains('r') || flags.contains('R') || longs.iter().any(|l| l == "recursive");
    let force = flags.contains('f') || longs.iter().any(|l| l == "force");
    let no_preserve = longs.iter().any(|l| l == "no-preserve-root");
    if paths.is_empty() {
        let missing = "rm: missing operand\nTry 'rm --help' for more information.";
        return if force {
            Streams::default()
        } else {
            Streams::fail(1, missing)
        };
    }
    let mut r = Streams::default();
    for p in &paths {
        let abs = sh.abs(p);
        let top_level = abs.matches('/').count() == 1;
        if recursive && (abs == "/" || (top_level && abs != "/tmp")) {
            sh.tag("destructive_command");
        }
        if abs == "/" {
            if !recursive {
                r.error(1, "rm: cannot remove '/': Is a directory");
            } else if !no_preserve {
                r.error(1, "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe");
            } else if sh.user.is_root() {
                let names: Vec<String> = sh
                    .fs
                    .list("/")
                    .unwrap_or_default()
                    .iter()
                    .map(|(n, _)| format!("/{n}"))
                    .collect();
                for n in &names {
                    let _ = sh.fs.remove(n, true);
                }
            } else {
                r.error(1, "rm: cannot remove '/': Permission denied");
            }
            continue;
        }
        let result = match sh.fs.node(&abs) {
            None => Err(FsError::NotFound),
            Some(n) if n.is_dir() && !recursive => Err(FsError::IsADirectory),
            Some(_) if !sh.fs.can_write(&abs, sh.actor()) => Err(FsError::Denied),
            Some(_) => sh.fs.remove(&abs, recursive),
        };
        match result {
            Ok(()) => {
                sh.created.remove(&abs);
            }
            Err(FsError::NotFound) if force => {}
            Err(e) => r.error(1, format!("rm: cannot remove '{p}': {}", e.message())),
        }
    }
    r
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

/// Why a `cp`/`mv` could not happen.
enum Xfer {
    NoSource,
    /// `cp` of a directory without `-r`.
    OmitDir,
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

pub(crate) fn transfer(sh: &mut Shell, args: &[String], moving: bool) -> Streams {
    let cmd = if moving { "mv" } else { "cp" };
    let (flags, longs, paths) = split_flags(args);
    let recursive = ['r', 'R', 'a'].iter().any(|c| flags.contains(*c))
        || longs.iter().any(|l| l == "recursive");
    let usage = format!("\nTry '{cmd} --help' for more information.");
    match paths.len() {
        0 => return Streams::fail(1, format!("{cmd}: missing file operand{usage}")),
        1 => {
            return Streams::fail(
                1,
                format!(
                    "{cmd}: missing destination file operand after '{}'{usage}",
                    paths[0]
                ),
            )
        }
        _ => {}
    }
    let (srcs, dst) = paths.split_at(paths.len() - 1);
    let dst = &dst[0];
    if srcs.len() > 1 && !sh.fs.is_dir(&sh.abs(dst)) {
        return Streams::fail(1, format!("{cmd}: target '{dst}' is not a directory"));
    }
    let mut r = Streams::default();
    for s in srcs {
        let (from, to) = (sh.abs(s), destination(sh, s, dst));
        match move_or_copy(sh, &from, &to, moving, recursive) {
            Ok(()) => {
                if moving {
                    if sh.created.remove(&from) {
                        sh.created.insert(to.clone());
                    }
                } else {
                    // a copy belongs to whoever made it, and is new
                    let (user, now) = (sh.user.name.clone(), sh.now());
                    let _ = sh.fs.set_owner(&to, &user, &user);
                    let _ = sh.fs.set_mtime(&to, now);
                    sh.created.insert(to.clone());
                }
                sh.note_write(&to);
            }
            Err(Xfer::OmitDir) => {
                r.error(1, format!("cp: -r not specified; omitting directory '{s}'"))
            }
            Err(Xfer::NoSource) => r.error(
                1,
                format!("{cmd}: cannot stat '{s}': No such file or directory"),
            ),
            Err(Xfer::Fs(e)) => {
                // GNU cp names only the destination; mv names both.
                let what = if moving {
                    format!("cannot move '{s}' to '{dst}'")
                } else {
                    format!("cannot create regular file '{dst}'")
                };
                r.error(1, format!("{cmd}: {what}: {}", e.message()));
            }
        }
    }
    r
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

/// `chmod MODE FILE...` and `chown OWNER FILE...`: the first operand is the
/// change, the rest are the files. Returns None (after reporting) if the
/// operands are incomplete.
fn change_operands<'a>(cmd: &str, rest: &'a [String]) -> Result<(&'a str, &'a [String]), Streams> {
    let usage = format!("\nTry '{cmd} --help' for more information.");
    match rest.split_first() {
        None => Err(Streams::fail(1, format!("{cmd}: missing operand{usage}"))),
        Some((spec, [])) => Err(Streams::fail(
            1,
            format!("{cmd}: missing operand after '{spec}'{usage}"),
        )),
        Some((spec, files)) => Ok((spec, files)),
    }
}

pub(crate) fn chmod(sh: &mut Shell, args: &[String]) -> Streams {
    let (_, _, rest) = split_flags(args);
    let (spec, files) = match change_operands("chmod", &rest) {
        Ok(ok) => ok,
        Err(usage) => return usage,
    };
    let mut r = Streams::default();
    for f in files {
        let abs = sh.abs(f);
        let Some(node) = sh.fs.node(&abs) else {
            r.error(
                1,
                format!("chmod: cannot access '{f}': No such file or directory"),
            );
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
            r.error(
                1,
                format!("chmod: changing permissions of '{f}': Operation not permitted"),
            );
            continue;
        }
        let _ = sh.fs.set_mode(&abs, (old & !0o777) | new);
    }
    r
}

pub(crate) fn chown(sh: &mut Shell, args: &[String]) -> Streams {
    let (_, _, rest) = split_flags(args);
    let (owner, files) = match change_operands("chown", &rest) {
        Ok(ok) => ok,
        Err(usage) => return usage,
    };
    let (user, group) = owner
        .split_once([':', '.'])
        .map_or((owner, ""), |(u, g)| (u, g));
    let mut r = Streams::default();
    for f in files {
        let abs = sh.abs(f);
        let Some(node) = sh.fs.node(&abs) else {
            r.error(
                1,
                format!("chown: cannot access '{f}': No such file or directory"),
            );
            continue;
        };
        if !sh.user.is_root() {
            r.error(
                1,
                format!("chown: changing ownership of '{f}': Operation not permitted"),
            );
            continue;
        }
        // an omitted user or group is left as it was
        let keep = |new: &str, old: &str| {
            if new.is_empty() {
                old.to_string()
            } else {
                new.to_string()
            }
        };
        let (user, group) = (keep(user, &node.meta.owner), keep(group, &node.meta.group));
        let _ = sh.fs.set_owner(&abs, &user, &group);
    }
    r
}
