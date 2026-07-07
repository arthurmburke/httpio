//! Raw DPDK FFI, generated at build time by bindgen from `wrapper.h` (see
//! `build.rs`). This includes real `#[repr(C)]` layouts for `rte_mbuf`,
//! `rte_eth_conf`, etc. -- so the safe wrappers read/write mbuf fields and
//! build device configs directly, and hardware offloads (checksum, RSS)
//! are just field writes. DPDK's `static inline` functions are reachable
//! via wrappers bindgen emits (`wrap_static_fns`).

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(improper_ctypes)]
// bindgen 0.71 doesn't wrap raw-pointer ops inside its generated `unsafe fn`
// bodies in `unsafe {}` blocks, which Rust 2024 warns about.
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
