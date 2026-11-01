# Poohbear

Poohbear is a honeypot: a fake server that looks like a real, slightly neglected machine on your network. Nothing legitimate should ever talk to it, so anyone who does is worth noticing. It lets attackers (and automated scanners) in, plays along, and writes down everything they do.

## What it does

- **Pretends to be a device.** Out of the box it poses as `plc-gw-03`, an Ubuntu gateway box that might sit in front of industrial equipment.
- **Lets people "log in".** The first few password guesses fail, then the next one works. Once inside, the attacker gets a believable shell with a welcome message and a "last login" line.
- **Answers commands convincingly.** `whoami`, `uname -a`, `pwd` and `cd` work. Anything unrecognized says "command not found", just like a real shell.
- **Plays along with malware downloads.** If the attacker runs `wget` or `curl` to pull down a payload, Poohbear pauses for a few seconds, prints a plausible download progress bar, and flags the attempt. Nothing is actually downloaded.
- **Records every session.** Each connection becomes a log entry in `sessions.jsonl`: who connected, what credentials they tried, what they typed, and which of those moments looked interesting (a successful login, a payload fetch, a credential guess).

It currently speaks three "languages":

| Mode | What it imitates |
|------|------------------|
| `ssh` | A Linux box with an SSH login and an interactive shell |
| `ftp` | An old vsftpd: USER/PASS login, then a believable control channel. Transfers are refused (no data connections) but flagged |
| `banner` | A simple text-based device on a raw TCP port (type `help`, `status`, `quit`) |

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

To try the simple text-device version instead, use `config/banner.yaml` and connect with `nc 127.0.0.1 2323`.

## Changing how it behaves

You don't need to touch any code to change the personality. Two small files control everything:

- **A config file** (`config/*.yaml`) says what to pretend to be: the hostname, the version banner, which port to listen on, how many visitors at once, how long a session may last, and where to write the log.
- **A track file** (`tracks/*.yaml`) is the script: who gets in, what each command prints, how long to hesitate, and what to flag as suspicious. Edit `tracks/ssh-linux-gateway.yaml` to add new commands or change the welcome message.

If a track file has a mistake, Poohbear refuses to start rather than running half-broken.

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
```

Ports 22 and 2222 use SSH; ports 21 and 2121 use FTP; port 23 uses the raw banner service. `HONEYPOT_LOG`
sets the JSONL session log path (the default is stdout). For full control over
listeners, tracks, persona, and limits, pass `--config` as shown above.

To enable real disposable container shells for SSH sessions, set
`HONEYPOT_BROKER` to the broker socket path. The honeypot does not access Docker
directly; see [docker/README.md](docker/README.md) for setup and security details.
Ports below 1024 require root or `CAP_NET_BIND_SERVICE`.

## Not done yet

- There is no fake file system yet, so `ls` and `cat` don't show anything realistic.
- FTP serves the control connection only: `PASV`/`PORT`/`LIST`/`STOR` are refused and tagged, so uploaded payloads are not captured.
- Only the three modes above exist.

## License

MIT
