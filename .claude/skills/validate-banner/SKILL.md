---
name: validate-banner
description: Build a honeypot container image locally, run it, and fingerprint it with nmap (connect scan, -sV at several intensities and timings, NSE banner/protocol scripts) to confirm the banner and nmap's service/version identification match the intended persona. Use when the user wants to validate, smoke-test or fingerprint-check a container build, Dockerfile or image of the honeypot, or asks whether a persona's banner "looks right" to scanners.
---

# Validate a honeypot container's banner

`validate.sh` (next to this file) does the whole run: build, start, wait for a
real answer, scan, check, clean up. It exits non-zero if any check fails.

## Inputs to settle first

- **What to build**: a Dockerfile (`--dockerfile PATH`, with `--context DIR`
  when the context isn't the Dockerfile's directory, usually the repo root)
  or an already-built image (`--image TAG`). If the user names neither, ask;
  don't guess at a Dockerfile.
- **Which port** (`--port`). The container gets `PORT=<port>` so the
  honeypot's env mode picks the protocol and built-in persona
  (`crates/hp-bin/src/services.rs`): 22/2222 ssh, 21/2121 ftp, 80/8080 http,
  443/8443 https, 23/2323 banner. To check several personas, run the script
  once per port. Building once and then passing `--image` saves rebuilds.
- **Expected banner**: the defaults are the built-in personas. If the image
  runs with a `--config` or a custom persona, pass `--expect-banner` (exact
  raw SSH/FTP line, or the HTTP `Server` header) and, if nmap's product
  string can't be derived from it, `--expect-product REGEX`. Read the config
  or track the image uses to get the real value. A config that listens on
  `127.0.0.1` can't be reached through a published port, so it needs `0.0.0.0`.

## Run

```
.claude/skills/validate-banner/validate.sh --dockerfile path/to/Dockerfile --context . --port 2222
.claude/skills/validate-banner/validate.sh --image poohbear:dev --port 8443 --out /tmp/vb-https
```

Other flags: `--protocol`, `--expect-service REGEX`, `--env K=V`,
`--run-arg ARG` (any extra `docker run` argument, e.g. `-v`), `--keep`
(leave the container up for manual poking), `--host-port N`,
`--scan-timeout T` (nmap `--host-timeout` per scan, default `4m`). The build
takes minutes the first time and a full run takes a few minutes more, so give
the Bash call a long timeout (600000 ms) or run it in the background.

The container is published on the **same host port** as `--port` by default.
This matters: nmap orders its probes by port number. On 8443 it tries TLS
first and reports `ssl/http`; on a random high port it sends plaintext first,
the honeypot answers in plain text, and nmap reports plain `http`. If the port
is busy the script falls back to a random one with a warning, and results
for that run should be treated as unrepresentative.

## What it checks

1. Raw grab (ncat for ssh/ftp/banner, curl's `Server` header for http/https)
   equals the expected banner exactly.
2. https only: a certificate is presented and its `notBefore` isn't within
   the last day (the self-signed cert should look backdated).
3. nmap profiles, all `-Pn -n -sT` against the published 127.0.0.1 port:
   `connect`, `version` (-sV), `version-light`, `version-all`,
   `version-fast-T5` (-T5) and `scripts` (-sV plus `banner`/`ssh-*`/`ftp-*`/
   `http-*`/`ssl-cert` per protocol). For each -sV run the port must be open,
   the service column must match (ssh, ftp, http, ssl/http) and the version
   column must match the expected product, e.g. `OpenSSH 8.9p1 Ubuntu
   3ubuntu0.6`, `vsftpd 3.0.3`, `nginx 1.18.0 (Ubuntu)`. A fingerprint
   submission block (`SF-Port...`) fails the check: it means nmap could not
   recognize the service, which is a giveaway.
4. The scripts run shows the `banner` or `http-server-header` output matching,
   and no NSE script crashed.
5. The container is still running after all the scans.

## Reporting

Report the pass/fail summary and, for every failure, the relevant line from
the nmap file in the `--out` directory (`nmap-<profile>.txt`) and what was
expected. Also note anything a scanner would find odd even when it passed,
such as a `Service Info` OS that contradicts the persona or algorithms from
`ssh2-enum-algos` that OpenSSH 8.9 wouldn't offer. If the container exited or
never answered, show the tail of `container.log` from the out directory.

## Caveats

- The `banner` protocol (23/2323) imitates no real product, so nmap can't
  identify it. It answers `?` to every probe, and `-sV` scans run until
  `--scan-timeout`. Expect those checks to fail unless the track is made to
  look like something nmap knows and `--expect-product` is passed.

- SYN scans (-sS) and OS detection (-O) are left out because they need root,
  and Docker Desktop's port proxy answers SYNs itself, so results would
  describe the proxy, not the honeypot.
- On Docker Desktop the published port accepts TCP before the honeypot
  listens, which is why readiness waits for real banner bytes.
- Keep `target/` out of the build context (a `.dockerignore` or
  `<Dockerfile>.dockerignore`). It's tens of GB and fills Docker's disk.
