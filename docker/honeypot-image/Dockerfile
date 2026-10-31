# The image every sandbox starts from (see `image:` in the broker policy).
#
#   docker build -t honeypot/ubuntu-gateway:1 docker/honeypot-image
#
# Sandboxes run with no network, so these tools exist only to look like what an
# attacker expects on a server: `wget` fails to resolve rather than being
# "command not found", which would give the game away.
FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wget curl iputils-ping iproute2 net-tools procps nano ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Accounts a login may map to (the broker policy's `users`).
RUN useradd -m -s /bin/bash -G dialout admin \
 && printf 'TODO: rotate historian creds\nplc-gw-02 firmware update scheduled for Q1\n' > /home/admin/notes.txt \
 && chown admin:admin /home/admin/notes.txt
