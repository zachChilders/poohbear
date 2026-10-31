# Adding a protocol

A protocol plugin is **only a wire format**. It parses bytes into `Event`s,
asks the session's behavior what to do, and writes the answer. Everything else
is provided. If you find yourself writing a command, a filesystem, a delay
loop, an input counter, or a log field name by hand, stop: it belongs in the
kit, the world, or `hp-log`.

## The recipe

1. **Crate.** `crates/hp-proto-<name>`, depending on `hp-core`, `hp-kit`,
   `hp-log` (and your wire library). Dev-depend on `hp-testkit`. Never depend
   on `hp-track` or `hp-world`.
2. **Implement `Protocol`.** `name()`, `default_ports()`, and
   `handle(stream, ctx)`. Start with:
   ```rust
   let mut driver = Driver::new(ctx.log, ctx.behavior, &ctx.limits);
   ```
   The driver guarantees `Connected` first and `Disconnected` exactly once
   (on drop, however the session ends), counts input against the cap, and
   logs inbound bytes. You get this by construction.
3. **Map the wire to events.**

   | The peer does… | You send the behavior… |
   |---|---|
   | connects | `driver.connect()` |
   | presents credentials | `Event::AuthAttempt { user, secret }` → `.verdict()` |
   | types a command line / runs a command | `Event::Command(line)` |
   | sends a structured request (a register read, an HTTP request) | `Event::Request { op, args }` |
   | sends opaque bytes | `Event::Raw(bytes)` |
   | disconnects | nothing: dropping the driver does it |

4. **Carry out the reply** with `hp_kit::apply(&mut out, driver.log(), actions,
   tty)`. Implement `Output` for your transport (a few lines) or use
   `StreamOut` for any async stream. `apply` handles `Send` (with tty newline
   translation), `Delay`, `Prompt` (sanitized) and `Close`. Ignore what does
   not apply to your protocol.
5. **Authentication.** `driver.react(&event).verdict()` gives a protocol-neutral
   `Verdict { granted(), welcome, prompt, delay, close }`. Log the attempt
   *before* sleeping `delay`, so it is captured if the peer gives up.
6. **Interactive protocols** use `hp_kit::term::LineEditor` for echo,
   backspace, Ctrl-C/D and escape sequences, and `sanitize` for anything that
   reaches a terminal.
7. **Refuse dangerous features and log them**, never ignore them silently:
   forwarding, file transfer, anything that would make the honeypot act on the
   network. Add a typed variant to `hp_log::Record` if there is something new
   worth recording; do not format log lines yourself.
8. **Register it** in `hp-bin`'s `plugin()` (validating persona-derived
   settings at startup so a bad config fails then, not per connection) and add
   a `config/<name>.yaml`.
9. **Write a track** that tells the story. Use `login:` / `shell:` to put the
   shared machine behind it. Do not script commands.

## Definition of done: "as deep as SSH"

- [ ] Handshake/banner matches the real implementation being imitated
      (checked against a reference with an independent client, not only your
      own test client: SSH's first real bug was found this way).
- [ ] Credentials are captured in full; the verdict comes from the behavior.
- [ ] The command surface is the shared world (`login:`/`shell:`), not
      per-protocol scripting.
- [ ] State persists through the session (a file written is a file read).
- [ ] Dangerous features are refused *and* logged.
- [ ] Limits hold: input cap, session timeout (supervised by `hp-bin`).
- [ ] `hp-testkit` conformance checks pass: `lifecycle`, `envelope`,
      `input_cap_enforced`, `no_raw_control_characters`.
- [ ] A real client drives it end to end (in-memory stream in tests; the real
      binary and a different client implementation once by hand).
- [ ] Hostile input cannot reach the terminal or the log unescaped.
- [ ] Fuzz target for the codec (parsers are pure functions where possible).

## Smallest possible example

`hp-proto-banner` is the reference: ~50 lines of logic for a raw TCP protocol.

```rust
async fn converse(stream: &mut dyn AsyncStream, driver: &mut Driver, banner: Option<&str>)
    -> anyhow::Result<()>
{
    let mut out = StreamOut(stream);
    if let Some(b) = banner {
        let line = Action::Send(Bytes::from(format!("{b}\r\n")));
        apply(&mut out, driver.log(), vec![line], false).await?;
    }
    let reply = driver.connect().into_actions();
    if apply(&mut out, driver.log(), reply, false).await?.flow == Flow::Close { return Ok(()) }

    let mut buf = [0u8; 4096];
    loop {
        let n = out.0.read(&mut buf).await?;
        if n == 0 || driver.receive(&buf[..n]).is_err() { return Ok(()) }
        let reply = driver.react(&Event::Raw(Bytes::copy_from_slice(&buf[..n]))).into_actions();
        if apply(&mut out, driver.log(), reply, false).await?.flow == Flow::Close { return Ok(()) }
    }
}
```

A framed binary protocol (Modbus, S7) replaces the read loop with a pure
`decode(&mut BytesMut) -> Option<Request>` function, which is what you fuzz,
and maps each request to `Event::Request { op, args }`.
