//! Tests against a real container runtime: do the restrictions actually hold?
//!
//! Skipped unless `HP_DOCKER_IMAGE` names a local image with bash and `script`
//! (for example `ubuntu:22.04`) and `docker` can reach a daemon:
//!
//!     HP_DOCKER_IMAGE=ubuntu:22.04 cargo test -p hp-broker --test docker

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hp_broker::{server, Broker, DockerRunner, Policy};
use hp_core::{AsyncStream, ShellBackend, ShellRequest, Terminal};
use hp_sandbox::ContainerBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Tests run side by side, each counting only its own sandboxes. The one test
/// that sweeps *every* sandbox takes the write lock, so it never runs beside them.
static SWEEP: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// A session id no other test uses; sandboxes carry it as a label.
fn session() -> String {
    format!(
        "docker-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// The image to test with, or None to skip.
fn image() -> Option<String> {
    let image = std::env::var("HP_DOCKER_IMAGE").ok();
    if image.is_none() {
        eprintln!("skipped: set HP_DOCKER_IMAGE to run the real-container tests");
    }
    image
}

/// A broker backed by real Docker, on a fresh socket.
fn broker(image: &str, extra: &str) -> PathBuf {
    let socket = std::env::temp_dir().join(format!(
        "hp-docker-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let policy = Policy::parse(&format!(
        "socket: {}\nimage: {image}\nhostname: plc-gw-03\nlimits: {{ pids: 64, memory: 128m, tmpfs: 16m }}\n{extra}",
        socket.display()
    ))
    .unwrap();
    let listener = server::bind(&policy).unwrap();
    tokio::spawn(Broker::new(policy, Arc::new(DockerRunner::new("docker"))).serve(listener));
    socket
}

fn terminal() -> Option<Terminal> {
    Some(Terminal {
        term: "xterm".into(),
        cols: 100,
        rows: 30,
    })
}

fn request(id: &str, command: Option<&str>, terminal: Option<Terminal>) -> ShellRequest {
    ShellRequest {
        session_id: id.into(),
        user: "root".into(),
        command: command.map(String::from),
        terminal,
    }
}

async fn shell(
    socket: &PathBuf,
    id: &str,
    command: Option<&str>,
    terminal: Option<Terminal>,
) -> Box<dyn AsyncStream> {
    ContainerBackend::new(socket)
        .start(request(id, command, terminal))
        .await
        .expect("a sandbox starts")
}

/// Read until `needle` appears (or the stream ends); returns everything read.
async fn read_until(s: &mut Box<dyn AsyncStream>, needle: &str) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(60), async {
        while !String::from_utf8_lossy(&got).contains(needle) {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&got)
        )
    });
    String::from_utf8_lossy(&got).into_owned()
}

/// Read until the output matches `pattern`. The terminal echoes what was
/// typed, so a marker must be one the *output* computes (`DD-$((40+2))` types
/// differently from the `DD-42` it prints).
async fn read_until_match(s: &mut Box<dyn AsyncStream>, pattern: &str) -> String {
    let re = regex::Regex::new(pattern).unwrap();
    let mut got = String::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(60), async {
        while !re.is_match(&got) {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for /{pattern}/; got {got:?}"));
    got
}

/// Sandboxes alive for session `id` (`None`: every sandbox there is).
fn live(id: Option<&str>) -> usize {
    let label = id.map_or("label=honeypot.managed=true".to_string(), |id| {
        format!("label=honeypot.session={id}")
    });
    let out = Command::new("docker")
        .args(["ps", "-aq", "--filter", &label])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .count()
}

async fn eventually(what: &str, ok: impl Fn() -> bool) {
    for _ in 0..300 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn an_interactive_shell_is_real_and_locked_down() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, ""), session());
    let mut s = shell(&socket, &id, None, terminal()).await;
    read_until(&mut s, "# ").await; // bash's own prompt

    // Each probe prints a token that does not appear in the command as typed
    // (the terminal echoes the command), so only the real output matches.
    let probes = [
        "echo HOST=$(hostname)",
        "echo USER=$(id -un)",
        "echo SIZE=$(stty size)",
        "echo CAPS=$(grep CapEff /proc/self/status | tr -d '\\t ')",
        "echo ROOTFS=$(touch /etc/pwned 2>&1 | head -c 60)",
        "echo TMP=$(echo hi > /tmp/f && cat /tmp/f)",
        "printf '#!/bin/sh\\necho RAN-%s $0\\n' payload > /tmp/x.sh; chmod +x /tmp/x.sh; echo EXEC=$(/tmp/x.sh)",
        "echo IFACES=$(ls /sys/class/net | tr '\\n' ',')",
        "echo NET=$(bash -c 'echo > /dev/tcp/1.1.1.1/80' 2>&1 | head -c 60)",
        "echo LEAK=$(env | grep -c HP_)",
        "echo END",
    ];
    for p in probes {
        s.write_all(format!("{p}\n").as_bytes()).await.unwrap();
    }
    let out = read_until(&mut s, "END\r\n").await;
    for (want, why) in [
        ("HOST=plc-gw-03", "the persona's host name"),
        ("USER=root", "the requested account"),
        ("SIZE=30 100", "the terminal size the peer asked for"),
        ("CAPS=CapEff:0000000000000000", "every capability dropped"),
        ("Read-only file system", "the root filesystem is read-only"),
        ("TMP=hi", "a writable scratch space exists"),
        (
            "EXEC=RAN-payload /tmp/x.sh",
            "dropped files can run (that is what we want to watch)",
        ),
        ("IFACES=lo,", "loopback is the only network interface"),
        ("LEAK=0", "how the command was delivered is not visible"),
    ] {
        assert!(out.contains(want), "{why}: expected {want:?} in\n{out}");
    }
    assert!(
        out.contains("NET=") && !out.contains("NET=\r"),
        "the connection attempt produced an error: {out}"
    );
    s.write_all(b"exit\n").await.unwrap();
    read_until(&mut s, "\u{0}never").await; // until the shell ends the stream
    eventually("the sandbox to be removed", || live(Some(&id)) == 0).await;
}

#[tokio::test]
async fn one_shot_commands_return_stdout_and_stderr() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, ""), session());
    let mut s = shell(
        &socket,
        &id,
        Some("echo out; echo err >&2; echo 'a b'"),
        None,
    )
    .await;
    let out = read_until(&mut s, "\u{0}never").await;
    for part in ["out", "err", "a b"] {
        assert!(out.contains(part), "{part:?} missing from {out:?}");
    }
    eventually("the sandbox to be removed", || live(Some(&id)) == 0).await;
}

#[tokio::test]
async fn hostile_commands_cannot_reach_the_host_or_change_the_sandbox() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, ""), session());
    // metacharacters are data: they run inside the sandbox, never on the host
    let marker = std::env::temp_dir().join(format!("hp-pwned-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let cmd = format!(
        "echo safe; touch {m}; id -un; echo '--privileged' $(echo subshell)",
        m = marker.display()
    );
    let mut s = shell(&socket, &id, Some(&cmd), None).await;
    let out = read_until(&mut s, "\u{0}never").await;
    assert!(
        out.contains("safe") && out.contains("--privileged subshell"),
        "{out}"
    );
    // `touch` ran, but in the sandbox's filesystem, not the host's
    assert!(!marker.exists(), "a command escaped to the host filesystem");
}

#[tokio::test]
async fn resource_limits_hold() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, ""), session());
    let mut s = shell(&socket, &id, None, terminal()).await;
    read_until(&mut s, "# ").await;
    // more processes than the pid limit allows, and more data than the tmpfs holds
    s.write_all(b"for i in $(seq 1 200); do sleep 3 >/dev/null & done 2>/tmp/err\nn=0; for d in /proc/[0-9]*; do n=$((n+1)); done; echo PROCS=$n\nwait; tail -n 2 /tmp/err; echo WAITED-$((1+1))\n").await.unwrap();
    let out = read_until_match(&mut s, r"WAITED-2\r\n").await;
    let procs: usize = regex::Regex::new(r"PROCS=(\d+)")
        .unwrap()
        .captures_iter(&out)
        .last()
        .unwrap()[1]
        .parse()
        .unwrap();
    assert!(
        procs <= 70,
        "the pid limit (64) did not hold: {procs} processes"
    );
    assert!(
        out.contains("Resource temporarily unavailable") || out.contains("retry"),
        "forking was refused: {out}"
    );

    s.write_all(
        b"dd if=/dev/zero of=/tmp/big bs=1M count=64 2>&1 | tail -n 1; echo DD-$((40+2))\n",
    )
    .await
    .unwrap();
    let out = read_until_match(&mut s, r"DD-42\r\n").await;
    // asked for 64 MiB; the 16 MiB tmpfs stops it short
    assert!(
        out.contains("copied") && !out.contains("67108864 bytes"),
        "the scratch space is capped: {out}"
    );
    drop(s);
    eventually("the sandbox to be removed", || live(Some(&id)) == 0).await;
}

#[tokio::test]
async fn dropping_the_connection_removes_the_container() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, ""), session());
    let mut s = shell(&socket, &id, None, terminal()).await;
    read_until(&mut s, "# ").await;
    // a foreground command that would run for ages, and a background one
    s.write_all(b"sleep 600 & sleep 600\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(live(Some(&id)), 1);
    drop(s);
    eventually("the sandbox to be removed", || live(Some(&id)) == 0).await;
}

#[tokio::test]
async fn capacity_is_enforced_with_real_sandboxes() {
    let Some(image) = image() else { return };
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker(&image, "max_sandboxes: 1\n"), session());
    let first = shell(&socket, &id, None, terminal()).await;
    let err = ContainerBackend::new(&socket)
        .start(request(&session(), None, terminal()))
        .await
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("refused: busy"), "{err:#}");
    drop(first);
    eventually("the sandbox to be removed", || live(Some(&id)) == 0).await;
}

#[tokio::test]
async fn a_missing_image_is_refused_vaguely_and_leaves_nothing_behind() {
    if image().is_none() {
        return;
    }
    let _shared = SWEEP.read().await;
    let (socket, id) = (broker("honeypot/does-not-exist:0", ""), session());
    let err = format!(
        "{:#}",
        ContainerBackend::new(&socket)
            .start(request(&id, None, None))
            .await
            .err()
            .unwrap()
    );
    assert!(err.contains("refused: unavailable"), "{err}");
    assert!(
        !err.to_lowercase().contains("docker") && !err.contains("No such image"),
        "Docker's error reached the peer: {err}"
    );
    assert_eq!(live(Some(&id)), 0);
}

#[tokio::test]
async fn leftovers_from_a_crashed_run_are_swept() {
    let Some(image) = image() else { return };
    let _exclusive = SWEEP.write().await;
    let created = Command::new("docker")
        .args([
            "create",
            "--label",
            "honeypot.managed=true",
            "--name",
            &format!("hp-leftover-{}", std::process::id()),
            &image,
            "true",
        ])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(live(None) >= 1);
    let removed = DockerRunner::new("docker")
        .remove_leftovers()
        .await
        .unwrap();
    assert!(removed >= 1);
    assert_eq!(live(None), 0);
}
