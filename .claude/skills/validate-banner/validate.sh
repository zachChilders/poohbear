#!/usr/bin/env bash
# Build (or take) a honeypot container image, run it locally, and fingerprint
# it with nmap under several settings to check the banner looks right.
#
#   validate.sh --dockerfile PATH [--context DIR] --port N [options]
#   validate.sh --image TAG --port N [options]
#
# Options:
#   --protocol P         ssh | ftp | http | https | banner (default: from --port,
#                        same table as crates/hp-bin/src/services.rs)
#   --expect-banner S    exact raw banner (ssh/ftp first line) or HTTP Server header
#   --expect-product RE  regex nmap -sV must report on the port line
#   --expect-service RE  regex for nmap's service column (default per protocol)
#   --env K=V            extra container env (repeatable); PORT=<port> is always set
#   --run-arg ARG        extra `docker run` argument (repeatable), e.g. a volume
#   --host-port N        host port to publish on (default: same as --port, so
#                        nmap orders its probes as it would against the real
#                        port; falls back to a random port if taken; 0 = random)
#   --scan-timeout T     nmap --host-timeout per scan (default 4m)
#   --out DIR            where nmap output goes (default: a temp dir)
#   --keep               leave the container running afterwards
#
# Exits 0 only if every check passes.
set -uo pipefail

dockerfile="" context="" image="" port="" protocol="" out="" keep=0
host_port="" scan_timeout=4m
expect_banner="" expect_product="" expect_service=""
envs=() run_args=()

die() { echo "error: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dockerfile) dockerfile="$2"; shift 2 ;;
    --context) context="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    --protocol) protocol="$2"; shift 2 ;;
    --expect-banner) expect_banner="$2"; shift 2 ;;
    --expect-product) expect_product="$2"; shift 2 ;;
    --expect-service) expect_service="$2"; shift 2 ;;
    --env) envs+=("-e" "$2"); shift 2 ;;
    --run-arg) run_args+=("$2"); shift 2 ;;
    --host-port) host_port="$2"; shift 2 ;;
    --scan-timeout) scan_timeout="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$port" ] || die "--port is required"
[ -n "$dockerfile" ] || [ -n "$image" ] || die "give --dockerfile or --image"
for tool in docker nmap ncat curl openssl; do
  command -v "$tool" >/dev/null || die "$tool not found on PATH"
done

if [ -z "$protocol" ]; then
  case "$port" in
    22|2222) protocol=ssh ;;
    21|2121) protocol=ftp ;;
    80|8080) protocol=http ;;
    443|8443) protocol=https ;;
    23|2323) protocol=banner ;;
    *) die "can't infer protocol for port $port; pass --protocol" ;;
  esac
fi

# Defaults are the built-in personas (env mode, no --config).
case "$protocol" in
  ssh)
    : "${expect_banner:=SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6}"
    : "${expect_service:=^ssh$}"
    scripts="banner,ssh-hostkey,ssh2-enum-algos,ssh-auth-methods" ;;
  ftp)
    : "${expect_banner:=220 (vsFTPd 3.0.3)}"
    : "${expect_service:=^ftp$}"
    scripts="banner,ftp-anon,ftp-syst" ;;
  http)
    : "${expect_banner:=nginx/1.18.0 (Ubuntu)}"
    : "${expect_service:=^http$}"
    scripts="http-server-header,http-title,http-headers" ;;
  https)
    : "${expect_banner:=nginx/1.18.0 (Ubuntu)}"
    : "${expect_service:=^(ssl/http|ssl/https|https)$}"
    scripts="ssl-cert,http-server-header,http-title,http-headers" ;;
  banner)
    scripts="banner" ;;
  *) die "unknown protocol: $protocol" ;;
esac

# What nmap's version probes should turn a known banner into.
if [ -z "$expect_product" ]; then
  case "$expect_banner" in
    SSH-2.0-OpenSSH_*)
      # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 -> OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
      v=${expect_banner#SSH-2.0-OpenSSH_}; v=${v%% *}
      expect_product="OpenSSH ${v//./\\.}" ;;
    *vsFTPd\ *)
      v=${expect_banner##*vsFTPd }; v=${v%%)*}
      expect_product="vsftpd ${v//./\\.}" ;;
    nginx/*)
      v=${expect_banner#nginx/}; v=${v%% *}
      expect_product="nginx ${v//./\\.}" ;;
  esac
fi

out=${out:-$(mktemp -d "${TMPDIR:-/tmp}/validate-banner.XXXXXX")}
mkdir -p "$out"
pass=0 fail=0
ok()  { pass=$((pass+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

# ---- build -----------------------------------------------------------------
if [ -n "$dockerfile" ]; then
  [ -f "$dockerfile" ] || die "no such Dockerfile: $dockerfile"
  context=${context:-$(dirname "$dockerfile")}
  image=${image:-poohbear-validate:$protocol-$port}
  echo "==> docker build -f $dockerfile -t $image $context"
  docker build -f "$dockerfile" -t "$image" "$context" >"$out/build.log" 2>&1 \
    || { tail -40 "$out/build.log"; die "build failed (full log: $out/build.log)"; }
fi

# ---- run -------------------------------------------------------------------
# nmap picks probe order by port number (e.g. it tries TLS early on 443/8443
# but late on a random high port), so scan the real port number when we can.
host_port=${host_port:-$port}
if [ "$host_port" != 0 ] && lsof -nP -iTCP:"$host_port" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "warning: host port $host_port is busy; using a random one (nmap probe order may differ)" >&2
  host_port=0
fi
[ "$host_port" = 0 ] && host_port=""
echo "==> docker run $image (PORT=$port, protocol $protocol)"
cid=$(docker run -d -e "PORT=$port" ${envs[@]+"${envs[@]}"} \
  -p "127.0.0.1:$host_port:$port" ${run_args[@]+"${run_args[@]}"} "$image") \
  || die "docker run failed"
cleanup() {
  docker logs "$cid" >"$out/container.log" 2>&1
  if [ "$keep" = 1 ]; then echo "container left running: $cid"; else docker rm -f "$cid" >/dev/null 2>&1; fi
}
trap cleanup EXIT

hostport=$(docker port "$cid" "$port/tcp" | head -1 | sed 's/.*://')
[ -n "$hostport" ] || die "port $port was not published"
echo "    127.0.0.1:$hostport -> container:$port"

# Docker Desktop accepts connections on the published port before anything
# listens, so readiness means a real answer, not just an open socket.
grab() {
  case "$protocol" in
    ssh|ftp) ncat -w 3 -i 2 127.0.0.1 "$hostport" </dev/null 2>/dev/null | head -1 | tr -d '\r' ;;
    http)    curl -s -m 3 -o /dev/null -D - "http://127.0.0.1:$hostport/" | tr -d '\r' | sed -n 's/^[Ss]erver: //p' ;;
    https)   curl -sk -m 3 -o /dev/null -D - "https://127.0.0.1:$hostport/" | tr -d '\r' | sed -n 's/^[Ss]erver: //p' ;;
    banner)  printf 'help\r\n' | ncat -w 3 -i 2 127.0.0.1 "$hostport" 2>/dev/null | head -1 | tr -d '\r' ;;
  esac
}
got=""
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$cid")" = true ] \
    || { docker logs "$cid" 2>&1 | tail -20; die "container exited"; }
  got=$(grab); [ -n "$got" ] && break
  sleep 1
done

echo "==> raw banner"
echo "    got: $got"
if [ -z "$got" ]; then
  bad "no answer on port $hostport after 30s"
elif [ -n "$expect_banner" ] && [ "$got" != "$expect_banner" ]; then
  bad "raw banner is not \"$expect_banner\""
else
  ok "raw banner${expect_banner:+ matches \"$expect_banner\"}"
fi

if [ "$protocol" = https ]; then
  echo | openssl s_client -connect "127.0.0.1:$hostport" -servername plc-gw-03 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates >"$out/cert.txt" 2>&1
  sed 's/^/    /' "$out/cert.txt"
  start=$(sed -n 's/^notBefore=//p' "$out/cert.txt")
  if [ -z "$start" ]; then
    bad "no certificate presented"
  elif [ "$(date -j -f '%b %e %T %Y %Z' "$start" +%s 2>/dev/null || date -d "$start" +%s)" -gt $(( $(date +%s) - 86400 )) ]; then
    bad "certificate notBefore is within the last day (looks freshly generated)"
  else
    ok "certificate is backdated"
  fi
fi

# ---- nmap ------------------------------------------------------------------
# name|args. Connect scans (-sT) only: SYN scans need root and Docker Desktop's
# port proxy answers them for any published port anyway.
profiles=(
  "connect|-sT"
  "version|-sT -sV"
  "version-light|-sT -sV --version-light"
  "version-all|-sT -sV --version-all"
  "version-fast-T5|-sT -sV -T5"
  "scripts|-sT -sV --script $scripts"
)

for p in "${profiles[@]}"; do
  name=${p%%|*} args=${p#*|}
  file="$out/nmap-$name.txt"
  echo "==> nmap $args -p $hostport  ($name)"
  # shellcheck disable=SC2086
  nmap -Pn -n --host-timeout "$scan_timeout" $args -p "$hostport" -oN "$file" 127.0.0.1 >/dev/null 2>&1
  line=$(grep -E "^$hostport/tcp" "$file" | head -1)
  echo "    $line"
  if grep -q 'due to host timeout' "$file"; then
    bad "$name: nmap gave up after $scan_timeout (probes got no recognizable answer)"; continue
  fi
  state=$(echo "$line" | awk '{print $2}')
  [ "$state" = open ] || { bad "$name: port state is '${state:-missing}'"; continue; }
  [ "$name" = connect ] && { ok "$name: open"; continue; }

  service=$(echo "$line" | awk '{print $3}')
  product=$(echo "$line" | awk '{$1=$2=$3=""; sub(/^ +/, ""); print}')
  if [[ -n "$expect_service" && ! "$service" =~ $expect_service ]]; then
    bad "$name: service '$service' does not match /$expect_service/"
  elif grep -q '^SF-Port\|^SF:' "$file"; then
    bad "$name: nmap could not identify the service (fingerprint submission in $file)"
  elif [[ -n "$expect_product" && ! "$product" =~ $expect_product ]]; then
    bad "$name: version '$product' does not match /$expect_product/"
  else
    ok "$name: $service${product:+ / $product}"
  fi

  if [ "$name" = scripts ]; then
    sed -n '/^PORT/,/^Service Info\|^$/p' "$file" | grep '^|' | sed 's/^/    /'
    case "$protocol" in
      ssh|ftp)
        b=$(sed -n 's/^|_\{0,1\}banner: //p' "$file" | head -1)
        if [ "$b" = "$expect_banner" ]; then ok "banner script: $b"
        else bad "banner script saw '$b', want '$expect_banner'"; fi ;;
      http|https)
        h=$(sed -n 's/^|_\{0,1\}http-server-header: //p' "$file" | head -1)
        if [ "$h" = "$expect_banner" ]; then ok "http-server-header: $h"
        else bad "http-server-header is '$h', want '$expect_banner'"; fi ;;
    esac
    if grep -q 'ERROR: Script execution failed' "$file"; then
      bad "a script crashed against the service (see $file)"
    fi
  fi
done

# A clean honeypot should survive the scans.
if [ "$(docker inspect -f '{{.State.Running}}' "$cid")" = true ]; then
  ok "container still running after scans"
else
  bad "container died during scans"
fi

echo
echo "==> $pass passed, $fail failed   (nmap output and logs: $out)"
[ "$fail" -eq 0 ]
