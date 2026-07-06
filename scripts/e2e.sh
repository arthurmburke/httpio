#!/usr/bin/env bash
# End-to-end test of the HTTP client over the DPDK TCP stack.
#
# Wiring: a persistent kernel tap device (dtap0) carries frames between
# the DPDK net_tap vdev (our stack's port, 10.9.0.1) and the kernel
# network stack (10.9.0.2), where real HTTP servers listen:
#   - python http.server            :8080  plain HTTP/1.1
#   - python http.server + ssl      :8443  HTTPS, ALPN http/1.1
#   - nghttpd                       :9443  HTTPS, ALPN h2
# TLS uses a freshly generated custom CA; the client must be told to
# trust it via --ca, and resolves the cert's hostname via --resolve.
#
# Run inside the devcontainer as root (needs /dev/net/tun + NET_ADMIN):
#   sudo scripts/e2e.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo build --bin http_get
BIN="$TARGET_DIR/debug/http_get"

WORK=$(mktemp -d)
cleanup() {
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- kernel side of the wire ------------------------------------------
# Persistent tap so it exists (and keeps its IP) across the separate
# short-lived DPDK client processes that attach to it. multi_queue is
# required: DPDK's tap PMD attaches with IFF_MULTI_QUEUE, and TUNSETIFF
# on a persistent device fails with EINVAL unless the flags match.
ip tuntap add dev dtap0 mode tap multi_queue 2>/dev/null || true
ip addr replace 10.9.0.2/24 dev dtap0
ip link set dtap0 up

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

# --- servers on the kernel side ----------------------------------------
(cd "$WORK/docroot" && exec python3 -m http.server --bind 10.9.0.2 --protocol HTTP/1.1 8080) &
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
nghttpd -d "$WORK/docroot" -a 10.9.0.2 9443 "$WORK/server.key" "$WORK/server.pem" &
sleep 1

# -l 0-1: lcore 0 runs tokio (main), lcore 1 runs the TCP engine worker.
RUN=("$BIN" -l 0-1 --no-huge --vdev=net_tap0,iface=dtap0 -- 10.9.0.1)
TLS_ARGS=(--ca "$WORK/ca.pem" --resolve test.local=10.9.0.2)

check() { # name, expected-version-line, args...
    local name=$1 version=$2; shift 2
    local out err
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

# HTTP/2 connection reuse: two requests to the same h2 origin in one
# process must multiplex over a single pooled TCP connection.
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
err=$(mktemp)
H1URL=https://test.local:8443/hello.txt
out=$("${RUN[@]}" "$H1URL" "$H1URL" "${TLS_ARGS[@]}" 2>"$err") \
    || { echo "FAIL h1 double fetch: client error"; cat "$err"; exit 1; }
grep -q "connections_opened=2" "$err" \
    || { echo "FAIL h1 double fetch: expected 2 connections:"; grep connections_opened "$err"; exit 1; }
echo "PASS HTTP/1.1 remains connection-per-request"

# Negative: without --ca the server cert chains to an unknown CA, so the
# TLS handshake must be rejected -- proves validation is actually on.
if "${RUN[@]}" https://test.local:8443/hello.txt --resolve test.local=10.9.0.2 >/dev/null 2>"$WORK/nocaperr"; then
    echo "FAIL unknown-CA rejection: request unexpectedly succeeded"
    exit 1
fi
grep -qi "certificate" "$WORK/nocaperr" || { echo "FAIL unknown-CA rejection: unexpected error:"; cat "$WORK/nocaperr"; exit 1; }
echo "PASS unknown CA rejected"

echo "ALL E2E TESTS PASSED"
