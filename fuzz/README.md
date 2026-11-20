# Fuzzing the HTTP/2 codec

The parts of `dpdk::http::h2` that read what a server sends are fuzzed
through three entry points in `src/dpdk/http/h2/fuzzing.rs`:

| Target | Input | Checks, beyond not panicking |
|---|---|---|
| `h2_connection` | two control bytes, then the server's byte stream | no stream outlives its handle; connection flow-control credit is conserved; every request and body finishes when the connection ends; the driver finishes |
| `h2_hpack` | length-prefixed header blocks for one decoder | the dynamic table's size adds up and stays within its limit; the field limits hold |
| `h2_huffman` | a Huffman-coded string | decoding then encoding gives the input back, and the reverse |

`h2_connection` sends requests of every shape (no body, small and large
buffered bodies, a streamed body, HEAD) and feeds the input in pieces of a
size the first control byte picks; the control bytes also choose whether
the transport stops taking writes, whether the connection driver runs,
whether bodies are dropped unread, and whether the connection ends with
requests in flight.

## Without any extra tooling

The same entry points are driven by seeded random tests in the ordinary
suite (`random_frame_sequences_never_break_the_connection` and
`random_bytes_never_break_the_decoders`), a few seconds' worth by default.
`H2_FUZZ_ITERS` runs more:

```sh
H2_FUZZ_ITERS=400000 cargo test --lib h2::tests::random
```

A failure prints its seed and input.

## With libFuzzer

Needs a nightly toolchain and `cargo install cargo-fuzz`, in the DPDK
devcontainer (the crate links libdpdk). From the repository root:

```sh
# Seed the corpus with generated frame sequences (optional, but it gets
# the connection target past the preface at once).
H2_FUZZ_CORPUS=fuzz/corpus cargo test --lib write_fuzz_corpus -- --ignored

RUSTFLAGS="-C target-cpu=native" cargo +nightly fuzz run h2_connection -- -max_len=8192
RUSTFLAGS="-C target-cpu=native" cargo +nightly fuzz run h2_hpack -- -max_len=1024
RUSTFLAGS="-C target-cpu=native" cargo +nightly fuzz run h2_huffman -- -max_len=256
```

`RUSTFLAGS` is needed because cargo-fuzz replaces the flags in
`.cargo/config.toml`, and the crate's hasher needs the CPU's AES
instructions. The corpus, artifacts and build output are not checked in.
