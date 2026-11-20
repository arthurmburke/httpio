#![no_main]
//! See `httpio::dpdk::http::h2::fuzzing::huffman`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| httpio::dpdk::http::h2::fuzzing::huffman(data));
