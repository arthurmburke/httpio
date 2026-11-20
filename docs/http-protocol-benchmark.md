# HTTP/1.1 and HTTP/2: the DPDK codecs, hyper on DPDK, hyper on the kernel

Measured 2026-11-19 with `scripts/bench_h2.sh` (three repeats, medians).
Three clients against one kernel hyper server over a veth link:

- **dpdk**: this crate's codecs (`dpdk::http::h1`, `dpdk::http::h2`) over
  its TCP and TLS streams (`dpdk-h2` in the script's output).
- **dpdk-hyper**: hyper's clients over the same streams.
- **kernel**: hyper's clients over kernel sockets (tokio).

See `examples/bench_h2.rs` for the columns and
[h2-benchmark.md](h2-benchmark.md) for the method and environment (a Docker
development VM with an `af_packet` vdev, not a bare-metal NIC).

Two things to keep in mind when reading across columns:

- `client us` for the DPDK clients is HTTP (and TLS) processing only; their
  TCP work runs on the worker lcore and is not counted. For `kernel` the
  same polls contain the socket system calls, so the figure includes the
  kernel's client-side TCP work. It shows what the application thread
  spends per request, not a like-for-like protocol cost.
- Wall-clock latency is end to end and includes the kernel server for all
  three.

## One connection per request (`fresh`)

How this crate uses HTTP/1.1, with HTTP/2 put on the same footing: TCP
handshake, protocol preface, one exchange. Cleartext.

Client microseconds per request:

| Method | Bytes | h1 dpdk | h1 dpdk-hyper | h1 kernel | h2c dpdk | h2c dpdk-hyper | h2c kernel |
|---|---:|---:|---:|---:|---:|---:|---:|
| GET | 64 | 2.85 | 4.38 | 17.40 | 2.94 | 6.71 | 26.54 |
| GET | 16,384 | 5.43 | 6.54 | 21.03 | 4.71 | 8.48 | 31.18 |
| GET | 1,048,576 | 83.05 | 117.39 | 449.64 | 111.45 | 140.72 | 580.57 |
| POST | 64 | 2.75 | 4.67 | 17.99 | 2.85 | 7.76 | 28.45 |
| POST | 16,384 | 2.98 | 5.53 | 28.72 | 2.83 | 9.51 | 39.31 |
| POST | 1,048,576 | 4.75 | 32.84 | 408.40 | 14.62 | 103.40 | 616.49 |

Wall-clock p50, microseconds:

| Method | Bytes | h1 dpdk | h1 dpdk-hyper | h1 kernel | h2c dpdk | h2c dpdk-hyper | h2c kernel |
|---|---:|---:|---:|---:|---:|---:|---:|
| GET | 64 | 24.6 | 25.0 | 38.9 | 33.5 | 35.5 | 42.0 |
| GET | 16,384 | 32.9 | 32.5 | 45.3 | 40.0 | 40.2 | 51.6 |
| GET | 1,048,576 | 365.1 | 395.6 | 547.5 | 488.2 | 509.9 | 682.5 |
| POST | 64 | 24.9 | 25.5 | 39.4 | 32.5 | 34.7 | 44.4 |
| POST | 16,384 | 49.7 | 54.7 | 45.5 | 40.1 | 50.1 | 58.2 |
| POST | 1,048,576 | 1221.5 | 1242.1 | 744.8 | 1162.1 | 1243.2 | 899.5 |

## One reused connection (`sequential`, `concurrent32`)

How HTTP/2 is used. HTTP/1.1 has no row here: this crate's HTTP/1.1 codec
does not keep connections alive.

Client microseconds per request:

| Proto | Workload | Method | Bytes | dpdk | dpdk-hyper | kernel |
|---|---|---|---:|---:|---:|---:|
| h2c | sequential | GET | 64 | 0.84 | 2.42 | 7.84 |
| h2c | sequential | GET | 16,384 | 2.25 | 3.71 | 9.95 |
| h2c | sequential | GET | 1,048,576 | 103.80 | 132.87 | 312.07 |
| h2c | sequential | POST | 64 | 0.87 | 3.49 | 9.83 |
| h2c | sequential | POST | 16,384 | 0.95 | 4.18 | 16.91 |
| h2c | sequential | POST | 1,048,576 | 10.11 | 51.65 | 587.30 |
| h2c | concurrent32 | GET | 64 | 0.57 | 1.82 | 2.07 |
| h2c | concurrent32 | GET | 16,384 | 2.36 | 3.41 | 6.38 |
| tls | sequential | GET | 64 | 1.13 | 2.72 | 8.62 |
| tls | sequential | GET | 16,384 | 4.99 | 7.09 | 15.63 |
| tls | sequential | GET | 1,048,576 | 292.10 | 598.83 | 627.49 |
| tls | sequential | POST | 64 | 1.21 | 4.00 | 10.81 |
| tls | sequential | POST | 16,384 | 4.24 | 7.15 | 20.90 |
| tls | sequential | POST | 1,048,576 | 187.89 | 211.32 | 679.02 |
| tls | concurrent32 | GET | 64 | 0.79 | 2.06 | 2.25 |
| tls | concurrent32 | GET | 16,384 | 5.15 | 6.68 | 9.89 |

Wall-clock p50, microseconds:

| Proto | Workload | Method | Bytes | dpdk | dpdk-hyper | kernel |
|---|---|---|---:|---:|---:|---:|
| h2c | sequential | GET | 64 | 15.2 | 17.1 | 28.5 |
| h2c | sequential | GET | 16,384 | 23.0 | 23.5 | 32.3 |
| h2c | sequential | GET | 1,048,576 | 479.9 | 493.1 | 632.3 |
| h2c | sequential | POST | 64 | 15.3 | 18.2 | 30.4 |
| h2c | sequential | POST | 16,384 | 24.6 | 28.5 | 36.7 |
| h2c | sequential | POST | 1,048,576 | 1092.0 | 1126.3 | 867.8 |
| h2c | concurrent32 | GET | 64 | 2.6 | 4.1 | 4.4 |
| h2c | concurrent32 | GET | 16,384 | 9.4 | 9.9 | 11.0 |
| tls | sequential | GET | 64 | 15.9 | 17.9 | 29.5 |
| tls | sequential | GET | 16,384 | 28.6 | 30.3 | 42.2 |
| tls | sequential | GET | 1,048,576 | 629.4 | 805.2 | 710.4 |
| tls | sequential | POST | 64 | 16.0 | 19.2 | 31.2 |
| tls | sequential | POST | 16,384 | 33.0 | 32.3 | 42.0 |
| tls | sequential | POST | 1,048,576 | 1026.5 | 1040.8 | 959.4 |
| tls | concurrent32 | GET | 64 | 2.7 | 4.5 | 4.7 |
| tls | concurrent32 | GET | 16,384 | 11.9 | 12.6 | 12.9 |

## Reading it

**HTTP/1.1 against HTTP/2 in this crate.** On a connection of its own the
two codecs cost about the same for small requests (2.8-2.9 us of client
time), but HTTP/2 is slower end to end by 8-9 us, the extra round of
SETTINGS and acknowledgements on a new connection. For a 1 MiB download
HTTP/1.1 is cheaper (83 against 111 us; 365 against 488 us wall), having
no frames or flow control. HTTP/2's case is the reused connection: a small
request costs 0.84 us and 15 us wall, against 2.85 us and 25 us for an
HTTP/1.1 request that has to connect first, and 32 concurrent requests
share the connection at 2.6 us wall each.

**Against hyper on the same DPDK streams.** The crate's codecs use less
client time in every case, HTTP/1.1 included: 1.2-1.7x for small and
medium HTTP/1.1 requests, 2.3-4x for small HTTP/2 ones, and most for
uploads, which go out as slices of the caller's buffer (4.75 against 33 us
for a 1 MiB HTTP/1.1 POST). Wall-clock latency follows, by a smaller
margin, with two ties or small losses out of 28 cases (16 KiB HTTP/1.1
GET, 16 KiB TLS POST).

**Against hyper on the kernel.** For requests up to 16 KiB the DPDK path is
10-15 us faster end to end on every protocol and workload but one (a
16 KiB HTTP/1.1 POST on a new connection: 49.7 against 45.5 us), and the
application thread spends 4-18x less time per request. Downloads of 1 MiB
are faster on DPDK too (365-630 against 548-710 us).

**Where the kernel wins: 1 MiB uploads.** In all four upload cases the
kernel client finishes sooner (745-960 us against 1030-1240 us), with
either codec on the DPDK side. Client time is not the reason -- the codec
spends 5-15 us on a cleartext 1 MiB POST -- so the time is in the TCP send
path on this setup: the stack segments in software and hands `af_packet`
one packet per system call, where the kernel client hands the veth whole
segments. `docs/tcp-library-benchmark.md` found the same asymmetry for
bulk sends and attributes it to segmentation rather than to the library;
it needs a NIC with TSO to settle.

## Reproduce

```sh
scripts/bench_h2.sh > http.tsv
```

`BENCH_H2_WORKLOAD=fresh|reused` and `BENCH_H2_PROTO=h1|h2c|tls` select
parts of it; `BENCH_H2_KERNEL=0` leaves the kernel client out.
