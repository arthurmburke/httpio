#!/usr/bin/env bash
# End-to-end test of the HTTP client over the DPDK TCP stack.
#
# Wiring: a kernel tap device (dtap0) carries frames between the DPDK
# net_tap vdev (our stack's port, 10.9.0.1) and the kernel network stack
# (10.9.0.2), where real HTTP servers listen:
#   - python http.server            :8080  plain HTTP/1.1
#   - python http.server + ssl      :8443  HTTPS, ALPN http/1.1
#   - nghttpd                       :9443  HTTPS, ALPN h2
#   - python http.server            10.8.0.2:8081, off-subnet (on lo), for
#                                   the --gateway routing checks
# TLS uses a freshly generated custom CA; the client must be told to
# trust it via --ca, and resolves the cert's hostname via --resolve.
#
# Each check runs a fresh short-lived DPDK process. DPDK's net_tap PMD
# leaves a persistent multi_queue tap in an unusable state after a
# (-l 0-1, worker-lcore) process detaches, so the tap is fully torn down
# and recreated -- and the servers restarted onto the fresh device --
# before every process. `fresh_net` does this.
#
# Run inside the devcontainer as root (needs /dev/net/tun + NET_ADMIN):
#   sudo scripts/e2e.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build --bin http_get --bin ws_client
BIN="$TARGET_DIR/debug/http_get"
WSBIN="$TARGET_DIR/debug/ws_client"

WORK=$(mktemp -d)
SERVER_PIDS=()
cleanup() {
    kill "${SERVER_PIDS[@]}" 2>/dev/null || true
    kill $(jobs -p) 2>/dev/null || true
    ip link del dtap0 2>/dev/null || true
    ip addr del 10.8.0.2/32 dev lo 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- custom CA + server certificate ------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key"
openssl req -x509 -new -key "$WORK/ca.key" -out "$WORK/ca.pem" -days 1 \
    -subj "/CN=tcp e2e test CA"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/server.key"
openssl req -new -key "$WORK/server.key" -out "$WORK/server.csr" -subj "/CN=test.local"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -CAcreateserial -out "$WORK/server.pem" -days 1 \
    -extfile <(printf "subjectAltName=DNS:test.local")

mkdir -p "$WORK/docroot"
echo "hello from e2e" > "$WORK/docroot/hello.txt"

# --- net (re)initialization -------------------------------------------
# multi_queue is required: DPDK's tap PMD attaches with IFF_MULTI_QUEUE,
# and TUNSETIFF on a persistent device fails with EINVAL unless the flags
# match.
recreate_tap() {
    ip link del dtap0 2>/dev/null || true
    ip tuntap add dev dtap0 mode tap multi_queue
    ip addr add 10.9.0.2/24 dev dtap0
    ip link set dtap0 up
    # Off-subnet server address for the routing checks. arp_ignore=1 stops
    # the kernel answering ARP for it on dtap0 (by default Linux answers for
    # any local address on any interface). Needs a writable /proc/sys
    # (privileged container); the routing checks are skipped without it.
    ip addr replace 10.8.0.2/32 dev lo
    sysctl -qw net.ipv4.conf.dtap0.arp_ignore=1 2>/dev/null || true
}

start_servers() {
    (cd "$WORK/docroot" && exec python3 -m http.server --bind 10.9.0.2 --protocol HTTP/1.1 8080) &
    SERVER_PIDS+=($!)
    python3 - "$WORK" <<'PYEOF' &
import http.server, os, ssl, sys
work = sys.argv[1]
os.chdir(work + "/docroot")
handler = http.server.SimpleHTTPRequestHandler
handler.protocol_version = "HTTP/1.1"
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(work + "/server.pem", work + "/server.key")
ctx.set_alpn_protocols(["http/1.1"])
httpd = http.server.HTTPServer(("10.9.0.2", 8443), handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PYEOF
    SERVER_PIDS+=($!)
    nghttpd -d "$WORK/docroot" -a 10.9.0.2 9443 "$WORK/server.key" "$WORK/server.pem" &
    SERVER_PIDS+=($!)
    (cd "$WORK/docroot" && exec python3 -m http.server --bind 10.8.0.2 --protocol HTTP/1.1 8081) &
    SERVER_PIDS+=($!)
    sleep 1
}

stop_servers() {
    [ ${#SERVER_PIDS[@]} -gt 0 ] && kill "${SERVER_PIDS[@]}" 2>/dev/null || true
    wait "${SERVER_PIDS[@]}" 2>/dev/null || true
    SERVER_PIDS=()
}

# Fresh tap + fresh servers for the next DPDK process.
fresh_net() {
    stop_servers
    recreate_tap
    start_servers
}

# -l 0-1: lcore 0 runs tokio (main), lcore 1 runs the TCP engine worker.
RUN=("$BIN" -l 0-1 --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1)
TLS_ARGS=(--ca "$WORK/ca.pem" --resolve test.local=10.9.0.2)

check() { # name, expected-version-line, args...
    local name=$1 version=$2; shift 2
    local out err
    fresh_net
    err=$(mktemp)
    out=$("${RUN[@]}" "$@" 2>"$err") || { echo "FAIL $name: client error"; cat "$err"; exit 1; }
    grep -q "hello from e2e" <<<"$out" || { echo "FAIL $name: bad body: $out"; exit 1; }
    grep -q "$version" "$err" || { echo "FAIL $name: wrong protocol"; grep "HTTP/" "$err"; exit 1; }
    rm -f "$err"
    echo "PASS $name"
}

check "HTTP/1.1 plaintext"          "HTTP/1.1 200" http://10.9.0.2:8080/hello.txt
check "HTTP/1.1 over TLS (custom CA)" "HTTP/1.1 200" https://test.local:8443/hello.txt "${TLS_ARGS[@]}"
check "HTTP/2 over TLS (custom CA)"   "HTTP/2.0 200" https://test.local:9443/hello.txt "${TLS_ARGS[@]}"

# Transport options piped through requests. Corked connections hold the
# final segment until a manual flush; the CLI drives that flush itself
# (see http_get). A corked request always negotiates HTTP/1.1 -- a
# manually held tail can't share a multiplexed h2 connection -- so both
# corked checks target the h1 server and expect HTTP/1.1.
check "HTTP/1.1 TLS corked"         "HTTP/1.1 200" https://test.local:8443/hello.txt "${TLS_ARGS[@]}" --cork
check "HTTP/1.1 TLS corked + Nagle" "HTTP/1.1 200" https://test.local:8443/hello.txt "${TLS_ARGS[@]}" --cork --nagle
check "HTTP/1.1 plaintext Nagle"    "HTTP/1.1 200" http://10.9.0.2:8080/hello.txt --nagle

# Gateway routing: 10.8.0.2 is off the 10.9.0.0/24 subnet, reachable only
# through the kernel (10.9.0.2) acting as the router. With dtap0's
# arp_ignore=1 (see recreate_tap), a frame only gets there when the stack
# addresses it to the gateway's MAC.
fresh_net
if [ "$(cat /proc/sys/net/ipv4/conf/dtap0/arp_ignore)" = 1 ]; then
    RUN_ROUTED=("$BIN" -l 0-1 --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1/24)
    # Negative first: without --gateway the stack ARPs for 10.8.0.2 itself
    # and never gets an answer, so the request must time out. (It must run
    # before any connection to 10.8.0.2: a lingering kernel-side socket would
    # ARP from 10.8.0.2 and teach the stack its MAC.)
    if "${RUN_ROUTED[@]}" http://10.8.0.2:8081/hello.txt >/dev/null 2>"$WORK/unrouted_err"; then
        echo "FAIL no-gateway: off-subnet request unexpectedly succeeded"
        exit 1
    fi
    grep -q "timed out" "$WORK/unrouted_err" \
        || { echo "FAIL no-gateway: unexpected error:"; cat "$WORK/unrouted_err"; exit 1; }
    echo "PASS off-subnet peer unreachable without --gateway"

    fresh_net
    out=$("${RUN_ROUTED[@]}" http://10.8.0.2:8081/hello.txt --gateway 10.9.0.2 2>"$WORK/routed_err") \
        || { echo "FAIL routed via gateway: client error"; cat "$WORK/routed_err"; exit 1; }
    grep -q "hello from e2e" <<<"$out" || { echo "FAIL routed via gateway: bad body: $out"; exit 1; }
    echo "PASS off-subnet peer via --gateway"
else
    echo "SKIP gateway routing checks (/proc/sys read-only; run the container with --privileged)"
fi

# HTTP/2 connection reuse: two requests to the same h2 origin in one
# process must multiplex over a single pooled TCP connection.
fresh_net
H2URL=https://test.local:9443/hello.txt
err=$(mktemp)
out=$("${RUN[@]}" "$H2URL" "$H2URL" "${TLS_ARGS[@]}" 2>"$err") \
    || { echo "FAIL h2 reuse: client error"; cat "$err"; exit 1; }
[ "$(grep -c "hello from e2e" <<<"$out")" -eq 2 ] || { echo "FAIL h2 reuse: expected 2 bodies"; exit 1; }
grep -q "connections_opened=1" "$err" \
    || { echo "FAIL h2 reuse: expected 1 connection:"; grep connections_opened "$err"; exit 1; }
echo "PASS HTTP/2 connection reuse (2 requests, 1 connection)"

# ...and HTTP/1.1 has no multiplexing handle, so the same double-fetch
# against the h1 TLS server dials twice.
fresh_net
err=$(mktemp)
H1URL=https://test.local:8443/hello.txt
out=$("${RUN[@]}" "$H1URL" "$H1URL" "${TLS_ARGS[@]}" 2>"$err") \
    || { echo "FAIL h1 double fetch: client error"; cat "$err"; exit 1; }
grep -q "connections_opened=2" "$err" \
    || { echo "FAIL h1 double fetch: expected 2 connections:"; grep connections_opened "$err"; exit 1; }
echo "PASS HTTP/1.1 remains connection-per-request"

# Negative: without --ca the server cert chains to an unknown CA, so the
# TLS handshake must be rejected -- proves validation is actually on.
fresh_net
if "${RUN[@]}" https://test.local:8443/hello.txt --resolve test.local=10.9.0.2 >/dev/null 2>"$WORK/nocaperr"; then
    echo "FAIL unknown-CA rejection: request unexpectedly succeeded"
    exit 1
fi
# The client reports a handshake failure by its io::ErrorKind, not the TLS
# alert, so the message names the handshake rather than the certificate.
# The same server and URL succeed with --ca above, so the certificate is
# the only thing that differs here.
grep -qi "TLS handshake with the origin failed" "$WORK/nocaperr" \
    || { echo "FAIL unknown-CA rejection: unexpected error:"; cat "$WORK/nocaperr"; exit 1; }
echo "PASS unknown CA rejected"

echo "ALL E2E TESTS PASSED"
