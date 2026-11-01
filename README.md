# poohbear: single-protocol honeypot

One process serves one protocol. With no config file, the port decides:

    PORT=22 honeypot                      # ssh, scripted shell (built-in track)
    PORT=2222 honeypot                    # also ssh
    PORT=23 honeypot                      # raw banner service
    PORT=22 HONEYPOT_BROKER=/run/honeypot/broker.sock honeypot   # ssh with real shells

| Variable | Meaning |
|---|---|
| `PORT` | Listen port; looked up in `crates/hp-bin/src/services.rs` to pick the protocol and its built-in track. Unknown ports are refused with the list of known ones. |
| `HONEYPOT_BROKER` | Broker socket; turns on real container shells (see `docker/README.md`). |
| `HONEYPOT_LOG` | JSONL session log path (default: stdout). |

Ports below 1024 need `CAP_NET_BIND_SERVICE` or root. For full control (several
listeners, custom tracks, persona, limits) pass `--config` (examples in `config/`).
To add a protocol: write the plugin, register it in `main.rs`, add a row in `services.rs`.
