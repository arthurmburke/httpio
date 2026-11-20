# HTTP/2 codec versus hyper, over the DPDK stack

Measured 2026-11-19 with `scripts/bench_h2.sh` (five repeats, alternating
order). Both clients run over this crate's `TcpStream` / `TlsStream` on one
reused connection to the same kernel hyper server: `dpdk-h2` is the codec in
`src/dpdk/http/h2`, `dpdk-hyper` is hyper's HTTP/2 client through the
streams' `AsyncRead`/`AsyncWrite` faces, which is what the client used
before.

**Result:** by median the codec spends less client time than hyper in all
sixteen cases, from 1.09x (1 MiB download, cleartext) to 5.2x (1 MiB upload,
cleartext). In fifteen of them every repeat of ours is below every repeat of
hyper's; in the cleartext 1 MiB download the ranges overlap (one of our five
repeats, 148 us, is above hyper's 145 us).

## What is measured

- `client us`: time spent inside polls of the client's own futures -- the
  request, the connection driver, and the tasks hyper spawns through its
  executor -- per request. This is the client's processing cost with the
  waiting taken out: no kernel server, no veth link, no AF_PACKET. It does
  include TLS encryption and decryption (same for both) and the two clock
  reads per poll, which charges hyper a little more because it polls more.
  The TCP worker lcore is not included for either client.
- `wall p50 us`: request latency as the application sees it. Most of it is
  the kernel server and the link, so it moves far less than the client time.
- `polls`: polls of client futures per request.

`tls` is ALPN `h2` over TLS 1.3, the path `Client` takes. `h2c` is cleartext
with prior knowledge: the codec without the cipher. `concurrent32` keeps 32
GETs in flight on the connection; its figures are per request.

Environment: Docker Desktop Linux VM, aarch64, 18 virtual CPUs, Linux
7.0.14-linuxkit, Rust 1.96.1, DPDK 22.11.11, release build, `net_af_packet`
vdev over veth with offloads off. A development VM, not a bare-metal NIC
result: the port has no TSO, so TLS output is copied into packets by the
worker rather than attached.

## Client microseconds per request: median (min-max of five repeats)

| Proto | Workload | Method | Bytes | dpdk-h2 | dpdk-hyper | hyper / h2 | wall p50, h2 / hyper | polls, h2 / hyper |
|---|---|---|---:|---:|---:|---:|---:|---:|
| tls | sequential | GET | 64 | 1.24 (1.20-1.44) | 2.81 (2.78-3.01) | 2.27x | 16.1 / 18.4 | 3.0 / 9.0 |
| tls | sequential | GET | 16,384 | 5.37 (5.28-5.42) | 7.40 (7.30-7.89) | 1.38x | 28.9 / 31.1 | 5.0 / 10.9 |
| tls | sequential | GET | 1,048,576 | 311.45 (303.75-312.52) | 487.35 (351.54-606.05) | 1.56x | 615.7 / 675.0 | 202.5 / 234.7 |
| tls | sequential | POST | 64 | 1.24 (1.21-1.25) | 4.03 (4.02-4.07) | 3.25x | 16.5 / 19.5 | 3.0 / 14.0 |
| tls | sequential | POST | 16,384 | 4.30 (4.29-4.55) | 7.20 (6.99-7.25) | 1.67x | 32.8 / 32.5 | 4.5 / 14.8 |
| tls | sequential | POST | 1,048,576 | 189.25 (187.44-191.19) | 211.20 (210.29-214.33) | 1.12x | 1027.3 / 1037.3 | 14.8 / 23.4 |
| tls | concurrent32 | GET | 64 | 0.77 (0.77-0.78) | 2.04 (2.01-2.09) | 2.65x | 2.7 / 4.4 | 0.4 / 2.3 |
| tls | concurrent32 | GET | 16,384 | 5.61 (5.60-5.66) | 6.97 (6.91-7.02) | 1.24x | 11.6 / 12.5 | 4.0 / 5.3 |
| h2c | sequential | GET | 64 | 0.83 (0.81-0.84) | 2.44 (2.37-2.49) | 2.95x | 15.4 / 17.5 | 3.0 / 9.0 |
| h2c | sequential | GET | 16,384 | 2.96 (2.79-3.10) | 3.96 (3.89-4.16) | 1.34x | 23.4 / 24.1 | 5.0 / 11.9 |
| h2c | sequential | GET | 1,048,576 | 133.05 (128.76-148.24) | 145.10 (144.64-145.53) | 1.09x | 443.4 / 464.7 | 187.9 / 261.3 |
| h2c | sequential | POST | 64 | 0.85 (0.82-0.87) | 3.46 (3.37-3.48) | 4.05x | 15.5 / 18.2 | 3.0 / 14.0 |
| h2c | sequential | POST | 16,384 | 0.93 (0.89-1.00) | 4.34 (4.16-4.53) | 4.66x | 24.8 / 28.7 | 4.7 / 14.9 |
| h2c | sequential | POST | 1,048,576 | 9.94 (9.62-10.81) | 51.37 (49.66-52.42) | 5.17x | 1089.2 / 1124.2 | 15.7 / 25.7 |
| h2c | concurrent32 | GET | 64 | 0.55 (0.54-0.55) | 1.84 (1.81-1.85) | 3.36x | 2.6 / 4.1 | 0.3 / 2.3 |
| h2c | concurrent32 | GET | 16,384 | 2.58 (2.57-2.63) | 3.54 (3.54-3.60) | 1.37x | 8.7 / 9.5 | 5.8 / 6.1 |

hyper's TLS 1 MiB download varied widely between repeats (352-606 us); the
codec's did not. Wall-clock latency is lower with the codec in fifteen cases
and level in one (TLS 16 KiB upload, 32.8 against 32.5 us).

## Where the difference comes from

- **No task switch for a request.** hyper's connection task owns the
  transport, so a request crosses to it and back (nine polls for a small
  GET, fourteen for a small POST). Here the task that sent the request reads
  its own response: three polls (the third is consistent with the server
  sending the response head and body as separate segments; not verified
  with a capture).
- **One buffer per request.** HEADERS, the DATA header and a small body
  leave as one buffer: one TLS record, one segment.
- **Uploads are slices.** A large body goes out as slices of the caller's
  `Bytes` between nine-byte frame headers; cleartext, a 1 MiB upload costs
  10 us of client time against 51 us.
- **No Huffman or dynamic-table work on requests.**

The large downloads gain least because their cost is not the codec's. A
profile of the cleartext 1 MiB download puts about half of the client time
in the one copy that concatenates the body for the caller (`Body::collect`),
and the rest in reading the body: taking ~720 packet buffers from the TCP
stream and dispatching the frames in them. Over TLS, decryption and rustls's internal
copies dominate both clients. A caller that reads the body as slices
(`Body::poll_slice`) skips that copy entirely; this benchmark does not
measure that, since hyper has no equivalent.

## Two transport changes that came out of this

Both are in the TLS stream and help any caller, not only this codec:

- `TlsStream::poll_send_queue` encrypts a queue of buffers in one pass, so a
  frame header and the payload behind it share an output buffer (and small
  neighbours a record), as hyper's vectored writes already did.
- TLS output on ports without TSO was written into a buffer that was
  zero-filled for every write. With the codec's send pattern that fill cost
  more than the encryption of a 16 KiB record (12.8 us per upload, 5.0 us
  without it; hyper's pattern lost about 1 us to it). Output now goes to
  reusable heap blocks that are zeroed once (`DmaWriter::on_heap`), as the
  DMA path already worked. Ports with TSO never took this path, so this
  particular gain is specific to ports that copy.

## Reproduce

Inside the DPDK devcontainer, as root (needs network namespaces and
`ethtool`):

```sh
scripts/bench_h2.sh > h2.tsv
```

`BENCH_H2_REPEATS`, `BENCH_H2_ROUNDS`, `BENCH_H2_PROTO=tls|h2c`,
`BENCH_H2_METHOD`, `BENCH_H2_BYTES` and `BENCH_H2_CONCURRENCY` narrow or
resize the run; `BENCH_H2_MODES=dpdk-h2` runs one client;
`BENCH_H2_MODES=dpdk-client` runs the TLS cases through `Client` itself,
after checking that streamed uploads share its pooled connection; and
`BENCH_H2_WRAP="perf record -g -o /tmp/perf.data"` profiles it.
