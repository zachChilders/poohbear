# Architecture

One binary, one protocol per instance. Everything that is *not* a wire format
is shared, so each protocol is exactly as deep as the others.

```
 network
    │
┌───▼────────────────────────────────────────────────────────────┐
│ protocol plugin   hp-proto-*   wire format only                │  bytes ⇄ Event / Action
├────────────────────────────────────────────────────────────────┤
│ session kit       hp-kit       lifecycle, input cap, auth       │  same for every protocol
│                                verdicts, apply(), terminal      │
├────────────────────────────────────────────────────────────────┤
│ behavior          hp-track     the *story*: who gets in, what   │  YAML tracks
│                                to flag, pacing                 │
├────────────────────────────────────────────────────────────────┤
│ world             hp-world     the *machine*: filesystem, shell,│  YAML host spec
│                                users, processes, alerts        │
└────────────────────────────────────────────────────────────────┘
 contracts: hp-core (Event, Action, Behavior, Host)   output: hp-log (typed records)
```

## Who owns what

| Concern | Owner | Never in |
|---|---|---|
| Framing, crypto, protocol quirks | the plugin | kit, track, world |
| "Connected/Disconnected exactly once", input cap, rx logging | `hp-kit::Driver` | plugins |
| Reading an auth reply, carrying out Send/Delay/Prompt/Close | `hp-kit` | plugins |
| Line editing, tty newlines, prompt sanitizing | `hp-kit::term` | plugins |
| Who gets in, pacing, extra alerts, state | a track (`hp-track`) | plugins, world |
| Filesystem, ~60 commands, prompt, login banner, host alerts | `hp-world` | plugins, tracks |
| What is written to the log | `hp-log::Record` | everywhere else |

**Depth lives in the world and the kit, not in per-protocol code.** A new
protocol that serves a shell gets the same machine as SSH. A track stays short
(see `tracks/ssh-linux-gateway.yaml`: ~40 lines for a full SSH honeypot).

## Dependency rules

```
hp-log                       (leaf: record schema + sink)
hp-core    → hp-log          (contracts only)
hp-kit     → hp-core, hp-log (shared plumbing)
hp-world   → hp-core         (implements Host)
hp-track   → hp-core         (implements Behavior's engine; calls Host)
hp-proto-* → hp-core, hp-kit, hp-log      ← never hp-track / hp-world
hp-bin     → everything      (wiring, config, supervision)
hp-testkit → hp-core, hp-log (dev-dependency only)
```

A plugin depends on **contracts and the kit, never on the engine or the
world**. The track engine and the world meet only through `hp_core::Host`, and
plugins meet the track engine only through `hp_core::Behavior`. Any piece can
be replaced or faked in tests.

## One SSH session, end to end

1. `hp-bin::Server` accepts a TCP connection, enforces `max_sessions`, wraps
   the session in a timeout and panic guard, and creates the session's
   `Behavior` (a track `Session` + a fresh `Host` from `hp-world`).
2. `hp-proto-ssh` runs the SSH handshake. A password attempt becomes
   `Event::AuthAttempt` via the kit's `Driver`.
3. The track decides: `auth: true`, `login: "${user}"`. The world answers the
   login with a banner and the first prompt. The adapter in `hp-bin` hands the
   plugin the *actions* and writes tags/transitions to the log.
4. Each shell line becomes `Event::Command`. The track delegates with
   `shell: "${command}"`; the world runs it on the session's in-memory
   filesystem and replies with output, the new prompt, and any alerts.
5. The kit's `apply()` sends the output (translating newlines for a tty),
   remembers the prompt, and honors `Close`.

## Invariants (enforced in code, tested)

- **No real side effects.** No process is spawned, no socket is opened, no DNS
  is resolved. `wget`/`curl` write deterministic fake content into an
  in-memory filesystem. Executing a file only raises a tag.
- **Per-session isolation.** Every session has its own filesystem, user,
  environment and track state.
- **Bounded memory.** Input cap, log queue, filesystem size/node caps, output
  cap, string variable cap, parser limits, nesting depth.
- **Hostile input is data.** Log records have no free-form fields; strings are
  JSON-escaped; prompts and usernames are stripped of control characters.
- **Failures are contained.** A panic ends one session, never the listener.
