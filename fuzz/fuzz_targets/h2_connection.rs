#![no_main]
//! See `httpio::dpdk::http::h2::fuzzing::connection`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| httpio::dpdk::http::h2::fuzzing::connection(data));
