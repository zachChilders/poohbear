<p align="center">
  <img src="assets/poohbear.jpg" alt="Poohbear" width="300">
</p>

# Poohbear

Poohbear is a honeypot: a fake server that looks like a real, slightly neglected machine on your network. Nothing legitimate should ever talk to it, so anyone who does is worth noticing. It lets attackers (and automated scanners) in, plays along, and writes down everything they do.

## What it does

- **Pretends to be a device.** Out of the box it poses as `plc-gw-03`, an Ubuntu gateway box that might sit in front of industrial equipment.
- **Lets people "log in".** The first few password guesses fail, then the next one works. Once inside, the attacker gets a believable shell with a welcome message and a "last login" line.
- **Answers commands convincingly.** `whoami`, `uname -a`, `pwd` and `cd` work. Anything unrecognized says "command not found", just like a real shell.
- **Plays along with malware downloads.** If the attacker runs `wget` or `curl` to pull down a payload, Poohbear pauses for a few seconds, prints a plausible download progress bar, and flags the attempt. Nothing is actually downloaded.
- **Records every session.** Each connection becomes a log entry in `sessions.jsonl`: who connected, what credentials they tried, what they typed, and which of those moments looked interesting (a successful login, a payload fetch, a credential guess).

It currently speaks four "languages":

| Mode | What it imitates |
|------|------------------|
| `ssh` | A Linux box with an SSH login and an interactive shell |
| `ftp` | An old vsftpd: USER/PASS login, then a believable control channel. Transfers are refused (no data connections) but flagged |
| `http` | The gateway's web console behind nginx, over HTTP or HTTPS: a login page, leftover `.env` and `.git` files, and traps for common exploits and product probes |
| `banner` | A simple text-based device on a raw TCP port (type `help`, `status`, `quit`) |

Any of them can be served over TLS (see [TLS](#tls)).

## Running it

```
cargo run -p hp-bin -- --config config/ssh.yaml
```

Then, from another terminal:

```
ssh -p 2222 admin@127.0.0.1
```

Any password will eventually work. Watch `sessions.jsonl` fill up with what you did.

It listens on port 2222 so it doesn't need root. To expose it as a normal SSH port (22), forward the port to it.

To try FTP, use `config/ftp.yaml` and connect with `ftp -p 127.0.0.1 2121`.

To try the web console, use `config/http.yaml` and browse to `http://127.0.0.1:8080/`, or
`config/https.yaml` and `curl -k https://127.0.0.1:8443/`. Logging in fails twice and then
works. For `http`, the log also records every request (method, path, headers and body) and any
credentials it carried (Basic auth, or a login form posted as fields or JSON).

To try the simple text-device version instead, use `config/banner.yaml` and connect with `nc 127.0.0.1 2323`.

## Changing how it behaves

You don't need to touch any code to change the personality. Two small files control everything:

- **A config file** (`config/*.yaml`) says what to pretend to be: the hostname, the version banner, which port to listen on, how many visitors at once, how long a session may last, and where to write the log.
- **A track file** (`tracks/*.yaml`) is the script: who gets in, what each command prints, how long to hesitate, and what to flag as suspicious. Edit `tracks/ssh-linux-gateway.yaml` to add new commands or change the welcome message.

If a track file has a mistake, Poohbear refuses to start rather than running half-broken.

For the web console, `tracks/http-ops-portal.yaml` matches requests by `method`, `path`,
`query`, `headers` and `body`. What it sends back is either a whole response (status line,
headers, a blank line, then the body) or just a page body. Poohbear works out the
`Content-Length`, `Date` and `Server` headers itself, so a track can't get them wrong.

## TLS

Add a `tls:` section to any config to serve its listener over TLS:

```yaml
tls:
  cert: /etc/honeypot/tls/plc-gw-03.pem   # certificate chain, leaf first
  key: /etc/honeypot/tls/plc-gw-03.key
```

A certificate issued by your internal CA is the most convincing option. Without one, Poohbear
can generate a self-signed certificate at startup. It is dated as if an admin issued it months
ago, not seconds before the first connection:

```yaml
tls:
  self_signed:
    names: [plc-gw-03, plc-gw-03.ot.corp.local]
    organization: "Plant Operations"
```

Each connection's TLS greeting is logged before the handshake finishes, so it is recorded even
if the client then rejects the certificate. The record includes the server name the client
asked for, the protocols it offered and its [JA4](https://github.com/FoxIO-LLC/ja4)
fingerprint, which identifies the client software (for example, a scanning tool versus a
browser). Someone sending plain text to a TLS port (such as plain HTTP to 443) is flagged and
answered in plain text.

## Safe by design

- It never really runs anything the attacker types. Every response is made up.
- It has caps on simultaneous visitors, session length and how much data it will accept, so it can't easily be overwhelmed.

## Environment defaults and real shells

Without a config file, `PORT` selects the protocol and its built-in track:

```
PORT=22 honeypot
PORT=21 honeypot
PORT=2222 honeypot
PORT=23 honeypot
PORT=80 honeypot
PORT=443 honeypot
```

Ports 22 and 2222 use SSH; ports 21 and 2121 use FTP; ports 80 and 8080 use HTTP; ports 443 and
8443 use HTTPS; port 23 uses the raw banner service. HTTPS uses `HONEYPOT_TLS_CERT` and
`HONEYPOT_TLS_KEY` (PEM files) if both are set. Otherwise it generates a self-signed certificate
for `HONEYPOT_TLS_NAMES` (comma-separated; `plc-gw-03` by default). `HONEYPOT_LOG`
sets the JSONL session log path (the default is stdout). For full control over
listeners, tracks, persona, and limits, pass `--config` as shown above.

To enable real disposable container shells for SSH sessions, set
`HONEYPOT_BROKER` to the broker socket path. The honeypot does not access Docker
directly; see [docker/README.md](docker/README.md) for setup and security details.
Ports below 1024 require root or `CAP_NET_BIND_SERVICE`.

## Not done yet

- There is no fake file system yet, so `ls` and `cat` don't show anything realistic.
- FTP serves the control connection only: `PASV`/`PORT`/`LIST`/`STOR` are refused and tagged, so uploaded payloads are not captured.
- HTTP is HTTP/1.x only; clients that insist on HTTP/2 can't connect. Login state is per
  connection, so a tool that opens a new connection for every guess never gets in.
- Only the four modes above exist.

## License

MIT
