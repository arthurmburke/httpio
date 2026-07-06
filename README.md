# BypassIO (bypio)

A userspace TCP/IP stack over raw DPDK FFI bindings (bindgen-generated at
build time from the installed DPDK headers — no `dpdk-sys` crate), plus
an HTTPS-capable HTTP/1.1 + HTTP/2 client that uses it as its transport.
Terminates TCP directly on top of a DPDK ethdev port: Ethernet + ARP +
IPv4 + TCP, no kernel network stack involved.

## Status / what's implemented

- **Handshake**: active and passive open, basic simultaneous-open handling.
- **Reliability**: per-segment retransmit queue, RFC 6298 (Jacobson/Karels)
  RTO estimation with Karn's algorithm, exponential backoff, give-up after
  12 retransmits.
- **Congestion control**: Reno-style slow start, congestion avoidance, fast
  retransmit on 3 duplicate ACKs, fast recovery.
- **Flow control**: sliding send/receive windows; out-of-order segments are
  buffered and reassembled; cumulative ACKs.
- **Teardown**: FIN/ACK in both directions, simultaneous close, TIME_WAIT
  (shortened to 30s here instead of the traditional 2*MSL ~4 minutes).
- **RST handling**: resets on segments to unknown connections, on SYNs to a
  synchronized connection, and on repeated retransmit timeout.
- **Nagle / TCP_NODELAY**: Nagle's algorithm (RFC 9293 §3.7.4) on by
  default -- a sub-MSS tail segment waits for in-flight data to be acked;
  `TcpSocket::set_nodelay(true)` disables it per connection so small
  segments go out immediately.
- **Cork + manual flush**: `TcpSocket::set_cork(true)` holds the trailing
  partial segment (full-MSS segments still flow) until an explicit
  `flush()` -- a manual send trigger, like Linux `TCP_CORK`. `close()`
  and uncorking flush implicitly.
- **HTTP client** (`src/http/`): HTTP/1.1 and HTTP/2 via hyper's
  low-level `client::conn` API, HTTPS via rustls with the Mozilla
  (webpki) roots plus custom CAs (`HttpClientBuilder::add_root_ca_pem`),
  protocol selected by ALPN. The API speaks the `http` crate's types:
  `http::Request<Bytes>` in, `http::Response<Bytes>` out (bodies are
  collected, not streamed). The transport is `DpdkTcpStream`, a tokio
  `AsyncRead`/`AsyncWrite` adapter that pumps the DPDK engine on every
  poll (busy-poll, matching DPDK's run-to-completion model; use a
  `current_thread` tokio runtime). No DNS (this stack has no UDP): use
  IP-literal URLs or map hostnames with `HttpClientBuilder::resolve()`
  (curl `--resolve` style); certificates still validate against the
  hostname. HTTP/2 connections are pooled per origin and multiplexed
  (requests to the same host share one TCP+TLS connection until the
  server closes it); HTTP/1.1 is connection-per-request. No redirects.
  Per-request transport tuning: insert a `TcpOptions { nodelay, cork }`
  into the request's `http::Extensions` to control TCP_NODELAY and
  TCP_CORK-style coalescing for the connection that request uses (a
  corked connection releases its held tail at protocol flush points --
  end of a TLS flight, a complete request, a batch of h2 frames).
  `http_get` exposes these as `--cork` and `--nagle`.
- **Minimal ARP**: request/reply, since without it there's no way to
  address a real Ethernet frame to a peer.

Not implemented (explicitly out of scope): window scaling, SACK, timestamps,
delayed ACK, IPv6, IP fragmentation/options, multi-segment (chained) mbufs,
routing/gateway support (every peer must be on the same L2 segment).

## Building: use the devcontainer

DPDK is Linux-only (hugepages, UIO/VFIO, DPDK-supported NIC PMDs), so the
project builds and runs inside the devcontainer in
[`.devcontainer/`](.devcontainer/devcontainer.json): a Rust toolchain plus
Debian's DPDK 22.11 LTS dev packages and clang/libclang for bindgen. Open
the folder in VS Code and "Reopen in Container", or use the image
directly:

```sh
docker build -t tcp-dpdk-dev .devcontainer
docker run --rm -v "$PWD":/work -w /work tcp-dpdk-dev cargo build
```

The stack can be smoke-run inside the container with no hugepages and no
real NIC, using EAL's `--no-huge` mode and a null vdev:

```sh
cargo run -- --no-huge --vdev=net_null0 -- 10.0.0.1 7
```

### End-to-end tests (HTTP over a tap device)

[`scripts/e2e.sh`](scripts/e2e.sh) (run as root inside the container:
`sudo scripts/e2e.sh`) wires the stack's `net_tap` vdev to the kernel via
a persistent tap device, starts real HTTP servers on the kernel side
(python `http.server` for HTTP/1.1 plain + TLS, `nghttpd` for HTTP/2),
generates a throwaway CA + server certificate, and exercises the
`http_get` binary through all of them:

- HTTP/1.1 plaintext
- HTTP/1.1 over TLS with the custom CA (ALPN `http/1.1`)
- HTTP/2 over TLS with the custom CA (ALPN `h2`)
- and verifies the TLS handshake is *rejected* when the CA isn't trusted.

### Fetching a URL manually

```sh
cargo run --bin http_get -- --no-huge --vdev=net_tap0,iface=dtap0 -- \
    10.9.0.1 https://test.local:8443/ --ca ca.pem --resolve test.local=10.9.0.2
```

EAL args before `--`; then the stack's local IP and the URL. `--ca` adds
a trusted CA PEM (repeatable), `--resolve HOST=IP` maps a hostname to an
address (repeatable). Body goes to stdout, status/headers to stderr.

On machines without DPDK (e.g. macOS), `cargo check`/`clippy` still work:
`build.rs` falls back to non-linkable stub FFI declarations so the crate
type-checks, and `cargo build` fails only at the link step, by design.

Inside the devcontainer, `CARGO_TARGET_DIR` points at a named-volume
directory (`/home/vscode/.cargo-target`) rather than the bind-mounted
workspace. Don't remove that: sharing `target/` between the macOS host
and the container mixes incompatible artifacts and trips cargo's
mtime-based fingerprinting over Docker Desktop file sharing, which shows
up as confusing mid-build errors like ``crate `syn` required to be
available in rlib format``. It also keeps builds off slow VirtioFS and
persists incremental state across container rebuilds.

## The FFI layer: bindgen + a small C shim

`build.rs` generates the bindings at build time with **bindgen**: it runs
over [`csrc/wrapper.h`](csrc/wrapper.h) using the include flags from
`pkg-config --cflags libdpdk`, so struct layouts and exported-function
signatures (`rte_eal_init`, `rte_eth_rx_queue_setup`/`tx_queue_setup`,
`rte_eth_dev_start`/`stop`, `rte_eth_macaddr_get`,
`rte_eth_promiscuous_enable`, `rte_pktmbuf_pool_create`, ...) are
ABI-exact for the DPDK version actually installed. The allowlist in
`build.rs` keeps the generated file to just what the stack calls.
[`src/dpdk/ffi.rs`](src/dpdk/ffi.rs) includes the generated bindings under
`cfg(dpdk_bound)`, with a hand-written stub mirror as the type-check-only
fallback when DPDK isn't present.

A handful of the hottest DPDK functions/macros
(`rte_eth_rx_burst`/`tx_burst`, `rte_pktmbuf_alloc`/`alloc_bulk`/`free`,
`rte_pktmbuf_mtod`, `rte_pktmbuf_append`/`prepend`/`adj`/`trim`/`reset`,
`rte_pktmbuf_headroom`/`tailroom`, `rte_socket_id`) are `static inline` in
the DPDK headers: they're compiled into whatever C translation unit uses
them and never produce a linkable symbol in libdpdk.so, so neither bindgen
nor an `extern "C"` block can call them. [`csrc/shim.c`](csrc/shim.c) is a
few dozen one-line wrappers giving those inlines a real exported name
(`dpdk_shim_*`), compiled by `build.rs` against the same installed
headers. `rte_eth_dev_configure` also goes through the shim so the
version-sensitive `struct rte_eth_conf` is built (zeroed) in C against the
real header rather than replicated in Rust.

The safe wrappers (`src/dpdk/mbuf.rs` etc.) deliberately treat `rte_mbuf`
and `rte_mempool` as opaque pointers and access mbuf fields through shim
accessors, so the Rust side never depends on `rte_mbuf`'s layout
(cache-line split, conditional fields, bitfields) staying put across DPDK
versions.

Note on static linking: DPDK PMDs self-register via constructors, which
typically needs `-Wl,--whole-archive`/`--no-whole-archive` around the
driver libraries when linking statically. `build.rs` forwards `-l`/`-L`
tokens from `pkg-config --libs libdpdk` to cargo but can't represent
arbitrary linker flags — if a static-linking setup needs those, pass them
via `RUSTFLAGS`. The devcontainer uses Debian's shared DPDK libs, where
PMDs are auto-loaded at runtime from the system PMD directory instead.

## Running

```sh
sudo ./target/release/tcp -l 0-1 -n 4 -- 192.168.1.10 7
```

EAL arguments come before `--` (core list, memory channels, etc. — see
DPDK's EAL documentation); this app's own arguments (local IPv4 address,
listen port) come after. `src/main.rs` is a small echo server: it accepts
connections on the given port and bounces back whatever it reads.

Requires a DPDK-bound NIC (via `vfio-pci`/`igb_uio`) or a `--vdev`
virtio-user interface, plus hugepages configured (`/proc/sys/vm/nr_hugepages`
or a hugetlbfs mount) — standard DPDK environment setup, not specific to
this project.
