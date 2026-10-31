# Design: a real-shell (container) backend

**Status:** accepted: shells are served by real containers only; the emulator
(`hp-world`, left on the `phase-2-ssh` branch) is retired. No code yet.

## Why

An emulated shell (`hp-world`, parked on `phase-2-ssh`) is safe and runs
anywhere, but it is a performance: every command is something we wrote. A
real Linux shell removes that ceiling. Attackers can compile, run `python`,
install packages and run their payloads, and there is no fake `ls` to
fingerprint. The price is that a "got shell" attacker now executes real code
on our infrastructure.

This reverses the build plan's rule that the process never executes anything.
The proposal is to relax it for **one component** (the shell backend) and move
the guarantee from "nothing runs" to "whatever runs is in a disposable sandbox
that cannot reach anything".

## Options

| | Fidelity | Isolation | Needs | Notes |
|---|---|---|---|---|
| Emulator (`hp-world`) | medium | strongest: nothing executes | nothing | done; shallow for anything it does not implement |
| Container, plain runc/Docker | high | **weak**: shared host kernel | Docker | one kernel exploit is a host compromise |
| Container under gVisor (`runsc`) | high | strong: user-space kernel | `runsc` | reports kernel `4.4.0`, a fingerprint |
| microVM (Firecracker/Kata) | highest | strongest of the real options | KVM | real guest kernel, more ops |

Never a long-lived shared container: attackers would see and tamper with each
other's work. **Recommendation: one ephemeral sandbox per session, gVisor to
start, Firecracker where KVM is available.**

## Threats and mitigations

| Attacker tries to… | Mitigation |
|---|---|
| escape to the host | hardened runtime; no privileged mode, no host mounts, no extra capabilities, seccomp, `no-new-privileges`, non-root user, read-only root with a size-capped tmpfs |
| attack others through us (scan, DDoS, mine) | **egress denied by default**; verified by a test that must fail to reach anything. Optional "capture network" (below) |
| exhaust the host | cgroup limits on CPU, memory, PIDs, disk; no swap; wall-clock session timeout kills the sandbox; a global cap on concurrent sandboxes |
| contaminate later sessions | fresh sandbox from an immutable image each time, destroyed on exit |
| compromise the honeypot and pivot | **the honeypot process never holds the container runtime socket** (that is root on the host). A small broker owns it |
| be recognised as a container | strip `/.dockerenv`, fix `/proc/1/cgroup`; gVisor's `4.4.0` is the one we cannot hide (a reason to prefer Firecracker) |

### The broker

A tiny separate service, running as its own user, exposing three calls over a
unix socket: `create(session_id)`, `attach(handle) -> pty stream`,
`destroy(handle)`. It fixes the image, limits and network itself, so the
honeypot cannot ask for anything else, and it rate-limits and caps sandboxes.
A reaper destroys sandboxes whose session is gone. A compromised honeypot can
open shells, which is the product, but cannot become root.

### Optional capture network

With egress denied, `wget http://c2/x` fails, so we learn the URL but not what
the attacker does next. A capture network points DNS at a sinkhole and HTTP at
a recorder that logs every request and answers with canned content. The
attacker proceeds and we see the next stage, without a real fetch. Fetching
real content is a separate, riskier option and is off the table for now.

## How it fits the code

Today a `Behavior` answers one `Event` at a time. A real shell is a byte
stream on a pty, so it is a second path, not a replacement:

- `hp-core`: a `ShellBackend` contract: `open(pty) -> ShellStream` (async
  read/write, resize, close) and `exec(command)`.
- A new `Action::OpenShell`, emitted by a track step (`shell: passthrough`).
  The track still decides authentication, pacing, and *which* sessions get a
  real shell (everyone, a sample, only some credentials), which is also how
  cost is bounded.
- `hp-kit`: a `bridge()` that pumps bytes between the protocol channel and the
  `ShellStream`, enforcing the input cap and logging every byte as `rx`/`tx`
  through the existing `Driver`. SSH and (later) Telnet share it.
- The backend sits behind a trait, so tests use an in-memory fake and a
  different runtime (gVisor, Firecracker) is a new implementation, not a
  redesign.

The persona (users, files, hostname) is baked into the container image, so it
is defined once and is consistent across sessions.

## Where alerts come from

The emulator knows what a command means. A container only knows bytes, so
alerts need other sources:

| Alert | Source |
|---|---|
| full session record | terminal transcript (asciicast v2), referenced from the log |
| what ran | `execve` events with argv (eBPF/Falco/Tetragon on the host, or gVisor's runtime monitoring; to be verified) |
| `payload_fetch` | blocked or sinkholed egress attempts: destination, port, request |
| files dropped | diff of the sandbox's writable layer at exit: path, size, SHA-256; samples quarantined outside the honeypot's reach |
| `payload_exec` | an `execve` of a path that appears in the drop list |
| `persistence_attempt` | writes to known paths seen in the layer diff |
| `credential_access` | needs file-access auditing; deferred |

Alerts will be less semantic than an emulator's until this is built.

## Proposed configuration

```yaml
protocol: ssh
shell:
  runtime: runsc            # runsc | firecracker
  image: honeypot/ubuntu-gateway:2025-10
  network: none             # none | capture
  limits: { cpu: 1, memory: 256MiB, pids: 128, disk: 256MiB }
  max_sandboxes: 16
broker: /run/honeypot-broker.sock
```

## Milestones (each its own reviewable PR)

1. **Contract + bridge, no containers.** (in progress) `ShellBackend`, `Action::OpenShell`,
   `hp-kit::bridge`, SSH passthrough, tested in CI with an in-memory fake
   backend.
2. **Broker + container backend** with `runsc` locally, image build, and
   integration tests behind a CI job that has Docker.
3. **Observability:** transcript, exec events, layer diff, egress log.
4. **Hardening review:** escape and abuse tests (fork bomb, disk fill),
   proof that nothing leaves, teardown on crash, kill switch.

## Risks and open questions

- Needs a Linux host with `runsc` or KVM; not runnable on a Mac without a VM.
- Per-session memory times `max_sandboxes` means a much lower concurrency than
  the 256 sessions of a scripted shell.
- gVisor's `4.4.0` against Firecracker's KVM requirement: decided by where this
  will be deployed.
- Legal and abuse exposure of letting attackers run code on your infrastructure
  is yours to assess; the egress-denied test and a kill switch are the controls
  we can build.
- Multiple protocols on one persona (SSH and HTTP showing one box) would need a
  shared sandbox per source for a time window. Out of scope here.

## Decision

**Containers only.** The emulator is retired rather than kept as a fallback:
one implementation to harden and review. Sessions that should not get a real
shell (the track decides) get no shell, or the scripted replies a track can
already give.
