# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build
#
# `rust:alpine` is a native musl build container: both the compiler and the
# produced binary target musl, so no cross-linker setup is needed. Rust links
# musl targets statically by default, which is why the binary can run on a
# plain Alpine image with no libc or shared libraries.
#
# The one native dependency is `ring` (pulled in by rustls/russh), which
# compiles C and assembly; `build-base` provides musl-gcc for it.
# ---------------------------------------------------------------------------
FROM rust:1-alpine AS builder

RUN apk add --no-cache build-base

WORKDIR /app

COPY . .

# Cache the cargo registry and target directory across builds. The target
# directory is a cache mount, so the binary has to be copied out in the same
# RUN step (a mount does not persist into the next layer).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --locked --release -p hp-bin --bin honeypot \
 && strip target/release/honeypot \
 && cp target/release/honeypot /usr/local/bin/honeypot

# ---------------------------------------------------------------------------
# Runtime
#
# The binary is statically linked, so the image only needs busybox/Alpine and
# a non-root user. Logs go to stdout by default (one JSONL record per line),
# which is what `docker logs` expects; set HONEYPOT_LOG to write to a file.
# ---------------------------------------------------------------------------
FROM alpine:3.22

RUN addgroup -S honeypot \
 && adduser -S -D -H -G honeypot -h /var/lib/honeypot -s /sbin/nologin honeypot \
 && mkdir -p /var/lib/honeypot /data \
 && chown honeypot:honeypot /var/lib/honeypot /data

COPY --from=builder /usr/local/bin/honeypot /usr/local/bin/honeypot

WORKDIR /var/lib/honeypot
USER honeypot

# PORT selects both the protocol and its built-in track:
#   22/2222 ssh, 21/2121 ftp, 80/8080 http, 443/8443 https, 23 banner
ENV PORT=2222
EXPOSE 2222

# The binary handles SIGINT for graceful shutdown, but `docker stop` sends
# SIGTERM by default.
STOPSIGNAL SIGINT

ENTRYPOINT ["/usr/local/bin/honeypot"]
