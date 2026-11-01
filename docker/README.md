# Real shells in sandboxes

When the SSH track grants `open_shell`, the attacker can get a real Linux
shell. The honeypot never touches Docker: it asks a separate **broker**
process over a unix socket, and the broker starts one hardened, disposable
container per shell (no network, read-only root, all capabilities dropped,
pid/memory/tmpfs limits, removed when the connection ends).

1. Build the image: `docker build --network host -t honeypot/ubuntu-gateway:1 docker/honeypot-image`
2. Run the broker as its own user (it needs Docker access; the honeypot does not):
   `hp-broker --config config/broker.yaml`
3. Run the honeypot: `PORT=22 HONEYPOT_BROKER=/run/honeypot/broker.sock honeypot`
   (or `--config config/ssh-container.yaml`, where `shell.broker` names the socket).

Use `runtime: runsc` (gVisor) in the broker policy for production. Known gaps:
the container shares the host kernel (`uname` shows it), shell exit status is
always reported as 0, and window-resize is not forwarded.

Real-Docker tests: `HP_DOCKER_IMAGE=honeypot/ubuntu-gateway:1 cargo test -p hp-broker --test docker`.
