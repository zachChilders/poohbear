//! Commands that report on the machine and the session: who you are, what is
//! running, the network, and privilege escalation (which is refused, and
//! flagged).

use super::{dispatch, is_executable, split_flags, Streams};
use crate::shell::Shell;
use crate::timefmt::{date_default, strftime, Civil};

/// Groups the user belongs to, as (gid, name), primary first, from the
/// session's own `/etc/group`.
fn group_list(sh: &Shell) -> Vec<(u32, String)> {
    let name = &sh.user.name;
    let mut groups = vec![(sh.user.uid, name.clone())];
    let file = sh
        .fs
        .read("/etc/group")
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    for line in String::from_utf8_lossy(&file).lines() {
        let f: Vec<&str> = line.split(':').collect();
        if let [g, _, gid, members] = f[..] {
            if g != name && members.split(',').any(|m| m == name) {
                if let Ok(gid) = gid.parse() {
                    groups.push((gid, g.to_string()));
                }
            }
        }
    }
    groups
}

pub(crate) fn id(sh: &Shell, args: &[String]) -> Streams {
    let (flags, _, _) = split_flags(args);
    let groups = group_list(sh);
    let names = flags.contains('n');
    let one = |id: u32, name: &str| {
        if names {
            name.to_string()
        } else {
            id.to_string()
        }
    };
    let text = if flags.contains('u') {
        one(sh.user.uid, &sh.user.name)
    } else if flags.contains('g') {
        one(groups[0].0, &groups[0].1)
    } else if flags.contains('G') {
        groups
            .iter()
            .map(|(id, n)| one(*id, n))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let list = groups
            .iter()
            .map(|(id, n)| format!("{id}({n})"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "uid={}({}) gid={}({}) groups={list}",
            sh.user.uid, sh.user.name, groups[0].0, groups[0].1
        )
    };
    Streams::out(text + "\n")
}

pub(crate) fn groups(sh: &Shell) -> Streams {
    let names: Vec<String> = group_list(sh).into_iter().map(|(_, n)| n).collect();
    Streams::out(names.join(" ") + "\n")
}

pub(crate) fn uname(sh: &Shell, args: &[String]) -> Streams {
    let (flags, longs, _) = split_flags(args);
    let k = &sh.spec.kernel;
    let all = flags.contains('a') || longs.iter().any(|l| l == "all");
    let wants = |c: char| all || flags.contains(c);
    let mut parts: Vec<String> = Vec::new();
    if wants('s') || flags.is_empty() && longs.is_empty() {
        parts.push("Linux".into());
    }
    if wants('n') {
        parts.push(sh.spec.hostname.clone());
    }
    if wants('r') {
        parts.push(k.release.clone());
    }
    if wants('v') {
        parts.push(k.version.clone());
    }
    if wants('m') {
        parts.push(k.machine.clone());
    }
    if wants('p') {
        parts.push(if all {
            k.machine.clone()
        } else {
            "x86_64".into()
        });
    }
    if wants('i') {
        parts.push(if all {
            k.machine.clone()
        } else {
            "x86_64".into()
        });
    }
    if wants('o') {
        parts.push("GNU/Linux".into());
    }
    Streams::out(parts.join(" ") + "\n")
}

pub(crate) fn hostname(sh: &Shell, args: &[String]) -> Streams {
    let (flags, _, _) = split_flags(args);
    if flags.contains('I') || flags.contains('i') {
        let addrs: Vec<&str> = sh
            .spec
            .interfaces
            .iter()
            .filter(|i| i.name != "lo")
            .map(|i| i.addr.as_str())
            .collect();
        return Streams::out(addrs.join(" ") + " \n");
    }
    Streams::out(format!("{}\n", sh.spec.hostname))
}

fn uptime_text(sh: &Shell) -> String {
    let up = sh.uptime_secs();
    let (days, hours, mins) = (up / 86_400, up % 86_400 / 3600, up % 3600 / 60);
    let day_part = match days {
        0 => String::new(),
        1 => "1 day, ".into(),
        n => format!("{n} days, "),
    };
    let time_part = if days == 0 && hours == 0 {
        format!("{mins} min")
    } else {
        format!("{hours:>2}:{mins:02}")
    };
    let c = Civil::from_epoch(sh.now());
    format!(
        " {:02}:{:02}:{:02} up {day_part}{time_part},  1 user,  load average: 0.08, 0.03, 0.01",
        c.hour, c.min, c.sec
    )
}

pub(crate) fn uptime(sh: &Shell, args: &[String]) -> Streams {
    let (flags, _, _) = split_flags(args);
    if flags.contains('p') {
        let up = sh.uptime_secs();
        let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
        let mut parts = Vec::new();
        for (n, unit) in [
            (up / 86_400, "day"),
            (up % 86_400 / 3600, "hour"),
            (up % 3600 / 60, "minute"),
        ] {
            if n > 0 {
                parts.push(plural(n, unit));
            }
        }
        return Streams::out(format!("up {}\n", parts.join(", ")));
    }
    Streams::out(uptime_text(sh) + "\n")
}

pub(crate) fn date(sh: &Shell, args: &[String]) -> Streams {
    let now = sh.now();
    match args.iter().find_map(|a| a.strip_prefix('+')) {
        Some(fmt) => Streams::out(strftime(fmt, now) + "\n"),
        None => Streams::out(date_default(now) + "\n"),
    }
}

pub(crate) fn w(sh: &Shell) -> Streams {
    let c = Civil::from_epoch(sh.now());
    Streams::out(format!(
        "{}\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n{:<8} pts/0    {:<16} {:02}:{:02}    0.00s  0.04s  0.00s w\n",
        uptime_text(sh), sh.user.name, sh.spec.login_from, c.hour, c.min
    ))
}

pub(crate) fn who(sh: &Shell) -> Streams {
    let c = Civil::from_epoch(sh.now());
    Streams::out(format!(
        "{:<8} pts/0        {}-{:02}-{:02} {:02}:{:02} ({})\n",
        sh.user.name, c.year, c.month, c.day, c.hour, c.min, sh.spec.login_from
    ))
}

pub(crate) fn ps(sh: &Shell, args: &[String]) -> Streams {
    let (flags, _, rest) = split_flags(args);
    let aux = flags.contains('a') && flags.contains('u') || rest.iter().any(|a| a.contains("aux"));
    let ef = flags.contains('e') && flags.contains('f');
    // The session's own processes, so `ps` shows the shell running it.
    let (bash, ps_pid) = (2013 + sh.user.uid % 50, 2101 + sh.user.uid % 50);
    let mut procs: Vec<(String, u32, String)> = sh
        .spec
        .processes
        .iter()
        .map(|p| (p.user.clone(), p.pid, p.cmd.clone()))
        .collect();
    procs.push((sh.user.name.clone(), bash, "-bash".into()));
    procs.push((sh.user.name.clone(), ps_pid, "ps".into()));

    let mut out = String::new();
    if aux {
        out.push_str(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n",
        );
        for (user, pid, cmd) in &procs {
            let (vsz, rss) = (10_000 + pid * 37 % 180_000, 1_000 + pid * 11 % 40_000);
            let mem = f64::from(rss) / 40_250.0;
            out.push_str(&format!("{user:<8} {pid:>7}  0.0 {mem:>4.1} {vsz:>6} {rss:>5} ?        Ss   Oct28   0:0{} {cmd}\n", pid % 10));
        }
    } else if ef {
        out.push_str("UID          PID    PPID  C STIME TTY          TIME CMD\n");
        for (user, pid, cmd) in &procs {
            let ppid = if *pid == 1 {
                0
            } else if cmd.starts_with("ps") {
                bash
            } else {
                1
            };
            out.push_str(&format!(
                "{user:<8} {pid:>7} {ppid:>7}  0 Oct28 ?        00:00:0{} {cmd}\n",
                pid % 10
            ));
        }
    } else {
        out.push_str("    PID TTY          TIME CMD\n");
        out.push_str(&format!(
            "{bash:>7} pts/0    00:00:00 bash\n{ps_pid:>7} pts/0    00:00:00 ps\n"
        ));
    }
    Streams::out(out)
}

pub(crate) fn env(sh: &Shell, args: &[String]) -> Streams {
    if let Some(name) = args.first() {
        return match sh.env.get(name) {
            Some(v) => Streams::out(format!("{v}\n")),
            None => Streams {
                status: 1,
                ..Streams::default()
            },
        };
    }
    Streams::out(
        sh.env
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>(),
    )
}

pub(crate) fn export(sh: &mut Shell, args: &[String]) -> Streams {
    if args.is_empty() {
        return Streams::out(
            sh.env
                .iter()
                .map(|(k, v)| format!("declare -x {k}=\"{v}\"\n"))
                .collect::<String>(),
        );
    }
    for a in args {
        if let Some((k, v)) = a.split_once('=') {
            sh.env.insert(k.to_string(), v.to_string());
        }
    }
    Streams::default()
}

pub(crate) fn unset(sh: &mut Shell, args: &[String]) -> Streams {
    for a in args {
        sh.env.remove(a);
    }
    Streams::default()
}

pub(crate) fn history(sh: &Shell) -> Streams {
    Streams::out(
        sh.history
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:>5}  {l}\n", i + 1))
            .collect::<String>(),
    )
}

pub(crate) fn free(sh: &Shell, args: &[String]) -> Streams {
    let (flags, _, _) = split_flags(args);
    let m = &sh.spec.memory_kb;
    let swap = 2_097_148u64;
    let (buff, shared) = (m.total / 6 + m.total / 40, 12_380u64);
    let used = m.total - m.free - buff;
    let avail = m.free + m.total / 8;
    let cell = |kb: u64| -> String {
        if flags.contains('h') {
            let mib = kb as f64 / 1024.0;
            if mib >= 1024.0 {
                format!("{:.1}Gi", mib / 1024.0)
            } else {
                format!("{}Mi", mib as u64)
            }
        } else if flags.contains('m') {
            (kb / 1024).to_string()
        } else {
            kb.to_string()
        }
    };
    let w = 11;
    let row = |label: &str, vals: &[u64]| {
        let cells: String = vals.iter().map(|v| format!(" {:>w$}", cell(*v))).collect();
        format!("{label:<8}{cells}\n")
    };
    Streams::out(format!(
        "{:>20}{:>w1$}{:>w1$}{:>w1$}{:>w1$}{:>w1$}\n{}{}",
        "total",
        "used",
        "free",
        "shared",
        "buff/cache",
        "available",
        row("Mem:", &[m.total, used, m.free, shared, buff, avail]),
        row("Swap:", &[swap, 0, swap]),
        w1 = w + 1,
    ))
}

pub(crate) fn df(args: &[String]) -> Streams {
    let (flags, _, _) = split_flags(args);
    if flags.contains('h') {
        Streams::out(
            "Filesystem      Size  Used Avail Use% Mounted on\n\
             tmpfs           393M  1.2M  392M   1% /run\n\
             /dev/sda2        39G   11G   26G  30% /\n\
             tmpfs           2.0G     0  2.0G   0% /dev/shm\n\
             tmpfs           5.0M     0  5.0M   0% /run/lock\n\
             /dev/sda1       511M  6.1M  505M   2% /boot/efi\n\
             tmpfs           393M  4.0K  393M   1% /run/user/1000\n",
        )
    } else {
        Streams::out(
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n\
             tmpfs             402500     1208    401292   1% /run\n\
             /dev/sda2       40581564 11250344  27283732  30% /\n\
             tmpfs            2012508        0   2012508   0% /dev/shm\n\
             tmpfs               5120        0      5120   0% /run/lock\n\
             /dev/sda1         523244     6220    517024   2% /boot/efi\n\
             tmpfs             402500        4    402496   1% /run/user/1000\n",
        )
    }
}

fn octets(ip: &str) -> Option<[u8; 4]> {
    let mut it = ip.split('.').map(|p| p.parse::<u8>().ok());
    let a = [it.next()??, it.next()??, it.next()??, it.next()??];
    it.next().is_none().then_some(a)
}

pub(crate) fn ip(sh: &Shell, args: &[String]) -> Streams {
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    match sub {
        "a" | "addr" | "address" => {
            let mut out = String::new();
            for (i, itf) in sh.spec.interfaces.iter().enumerate() {
                let (ip, mask) = (
                    octets(&itf.addr).unwrap_or([0; 4]),
                    octets(&itf.netmask).unwrap_or([255, 0, 0, 0]),
                );
                let prefix: u32 = mask.iter().map(|b| b.count_ones()).sum();
                let brd: Vec<String> = ip
                    .iter()
                    .zip(mask)
                    .map(|(a, m)| (a | !m).to_string())
                    .collect();
                let lo = itf.name == "lo";
                let (flags, mtu, extra) = if lo {
                    (
                        "LOOPBACK,UP,LOWER_UP",
                        65_536,
                        "qdisc noqueue state UNKNOWN group default qlen 1000",
                    )
                } else {
                    (
                        "BROADCAST,MULTICAST,UP,LOWER_UP",
                        1500,
                        "qdisc fq_codel state UP group default qlen 1000",
                    )
                };
                out.push_str(&format!(
                    "{}: {}: <{flags}> mtu {mtu} {extra}\n",
                    i + 1,
                    itf.name
                ));
                let mac = itf
                    .mac
                    .clone()
                    .unwrap_or_else(|| "00:00:00:00:00:00".into());
                let (kind, brd_mac) = if lo {
                    ("loopback", "00:00:00:00:00:00")
                } else {
                    ("ether", "ff:ff:ff:ff:ff:ff")
                };
                out.push_str(&format!("    link/{kind} {mac} brd {brd_mac}\n"));
                if lo {
                    out.push_str(&format!(
                        "    inet {}/{prefix} scope host {}\n",
                        itf.addr, itf.name
                    ));
                } else {
                    out.push_str(&format!(
                        "    inet {}/{prefix} brd {} scope global {}\n",
                        itf.addr,
                        brd.join("."),
                        itf.name
                    ));
                }
                out.push_str("       valid_lft forever preferred_lft forever\n");
            }
            Streams::out(out)
        }
        "r" | "route" => {
            let Some(itf) = sh.spec.interfaces.iter().find(|i| i.name != "lo") else {
                return Streams::default();
            };
            let ip = octets(&itf.addr).unwrap_or([0; 4]);
            let mask = octets(&itf.netmask).unwrap_or([255, 255, 255, 0]);
            let net: Vec<String> = ip
                .iter()
                .zip(mask)
                .map(|(a, m)| (a & m).to_string())
                .collect();
            let prefix: u32 = mask.iter().map(|b| b.count_ones()).sum();
            let gw = format!("{}.{}.{}.1", net[0], net[1], net[2]);
            Streams::out(format!(
                "default via {gw} dev {0} proto static\n{1}/{prefix} dev {0} proto kernel scope link src {2}\n",
                itf.name, net.join("."), itf.addr
            ))
        }
        "" => Streams::fail(255, "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"),
        other => Streams::fail(
            1,
            format!("Object \"{other}\" is unknown, try \"ip help\"."),
        ),
    }
}

pub(crate) fn which(args: &[String]) -> Streams {
    let (mut out, mut status) = (String::new(), 0);
    for a in args.iter().filter(|a| !a.starts_with('-')) {
        if is_executable(a) {
            out.push_str(&format!("/usr/bin/{a}\n"));
        } else {
            status = 1;
        }
    }
    Streams {
        out: out.into_bytes(),
        status,
        ..Streams::default()
    }
}

pub(crate) fn sudo(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (mut i, mut interactive) = (0, false);
    while i < args.len() && args[i].starts_with('-') {
        match args[i].as_str() {
            "-i" | "-s" => interactive = true,
            "-u" | "-g" => i += 1,
            _ => {}
        }
        i += 1;
    }
    if !sh.user.can_sudo() {
        sh.tag("privesc_attempt");
        return Streams::fail(
            1,
            format!(
                "{} is not in the sudoers file.  This incident will be reported.",
                sh.user.name
            ),
        );
    }
    if i >= args.len() {
        if interactive {
            sh.become_user("root");
            return Streams::default();
        }
        return Streams::fail(1, "usage: sudo -h | -K | -k | -V");
    }
    // Run the command as root, then go back to being ourselves.
    let saved = sh.user.clone();
    sh.user = sh.spec.account("root").expect("validated").clone();
    let result = sh.nested(|sh| dispatch(sh, &args[i], &args[i + 1..], stdin));
    sh.user = saved;
    result
}

pub(crate) fn su(sh: &mut Shell, args: &[String]) -> Streams {
    if sh.user.is_root() {
        if let Some(target) = args.iter().rfind(|a| !a.starts_with('-')) {
            sh.become_user(target);
        }
        return Streams::default();
    }
    sh.tag("privesc_attempt");
    Streams::fail(1, "su: Authentication failure")
}

pub(crate) fn crontab(sh: &mut Shell, args: &[String]) -> Streams {
    let (flags, _, rest) = split_flags(args);
    if flags.contains('l') {
        return Streams::fail(1, format!("no crontab for {}", sh.user.name));
    }
    if flags.contains('r') {
        return Streams::default();
    }
    // Installing a crontab (`crontab -`, `crontab file`) is persistence.
    if args.iter().any(|a| a == "-") || !rest.is_empty() {
        sh.tag("persistence_attempt");
    }
    Streams::default()
}

/// `nohup`, `setsid`, `time`, `command`, `exec`: run what follows.
pub(crate) fn wrapper(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let args: Vec<String> = args
        .iter()
        .skip_while(|a| a.starts_with('-') && *a != "-v")
        .cloned()
        .collect();
    match args.first().map(String::as_str) {
        None => Streams::default(),
        Some("-v") => which(&args[1..]),
        Some(cmd) => sh.nested(|sh| dispatch(sh, cmd, &args[1..], stdin)),
    }
}

/// `sh`/`bash`: `-c 'line'`, a script file, or a script on stdin.
pub(crate) fn shell(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let from_fetch = sh.pipe_from_fetch;
    if let Some(pos) = args.iter().position(|a| a == "-c") {
        let line = args.get(pos + 1).cloned().unwrap_or_default();
        return Streams::out(sh.exec_text(&line));
    }
    if let Some(file) = args.iter().find(|a| !a.starts_with('-')) {
        let abs = sh.abs(file);
        return match sh.fs.node(&abs) {
            None => Streams::fail(127, format!("bash: {file}: No such file or directory")),
            Some(n) if n.is_dir() => Streams::fail(126, format!("bash: {file}: Is a directory")),
            Some(_) => {
                if sh.created.contains(&abs) {
                    sh.tag("payload_exec");
                }
                Streams::default()
            }
        };
    }
    // A script piped in. Text the peer typed (`echo id | sh`) is run; content
    // that came from a download is not, but is flagged.
    if from_fetch {
        sh.tag("payload_exec");
        return Streams::default();
    }
    match std::str::from_utf8(stdin) {
        Ok(text) => {
            let mut out = Vec::new();
            for line in text.lines() {
                out.extend(sh.exec_text(line));
            }
            Streams::out(out)
        }
        Err(_) => Streams::default(),
    }
}
