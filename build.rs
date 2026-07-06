//! Builds the real DPDK FFI layer when DPDK is available:
//!
//! 1. **bindgen** runs over `csrc/wrapper.h` with the include flags from
//!    `pkg-config --cflags libdpdk`, generating ABI-exact Rust bindings
//!    (struct layouts, exported-function signatures) for the DPDK version
//!    actually installed on this machine. Output goes to
//!    `$OUT_DIR/dpdk_bindings.rs`, included by `src/dpdk/ffi.rs` under
//!    `cfg(dpdk_bound)`.
//! 2. **cc** compiles `csrc/shim.c` against the same headers. The shim
//!    exists because a handful of DPDK datapath functions
//!    (`rte_eth_rx_burst`, `rte_pktmbuf_alloc`, ...) are `static inline`
//!    in the headers: they never appear as linkable symbols in
//!    libdpdk.so, so neither bindgen nor a plain `extern "C"` block can
//!    reach them. The shim wraps each in a real exported symbol.
//! 3. The `-l`/`-L` tokens from `pkg-config --libs libdpdk` are forwarded
//!    to cargo for the final link.
//!
//! DPDK is Linux-only. Off Linux (or if libdpdk isn't installed) all of
//! the above is skipped and `cfg(dpdk_bound)` is left unset, which makes
//! `src/dpdk/ffi.rs` fall back to non-linkable stub declarations so
//! `cargo check` still type-checks the whole crate. Use the devcontainer
//! in `.devcontainer/` for a real build.

use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=csrc/shim.c");
    println!("cargo:rerun-if-changed=csrc/wrapper.h");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    // Declare the custom cfg so rustc's check-cfg lint knows to expect it.
    println!("cargo:rustc-check-cfg=cfg(dpdk_bound)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        println!(
            "cargo:warning=tcp: DPDK is Linux-only; building with stub (non-linkable) FFI \
             declarations on target_os=\"{target_os}\". Use the devcontainer for a real build."
        );
        return;
    }

    let exists = Command::new("pkg-config")
        .args(["--exists", "libdpdk"])
        .status();
    if !matches!(exists, Ok(status) if status.success()) {
        println!(
            "cargo:warning=tcp: pkg-config could not find `libdpdk`; building with stub \
             (non-linkable) FFI declarations. Install the DPDK dev packages (see \
             .devcontainer/Dockerfile) for a real build."
        );
        return;
    }

    let cflags = pkg_config_output(&["--cflags", "libdpdk"]);
    let libs = pkg_config_output(&["--libs", "libdpdk"]);

    generate_bindings(&cflags);

    let mut build = cc::Build::new();
    build.file("csrc/shim.c");
    for flag in cflags.split_whitespace() {
        build.flag(flag);
    }
    build.compile("dpdk_shim");

    // pkg-config for libdpdk emits the library list DPDK needs. Forward
    // each -L/-l token to cargo for the final binary link. Other flags
    // (e.g. -Wl,--whole-archive groups emitted for static PMD linking)
    // aren't representable as cargo link directives; pass those via
    // RUSTFLAGS if a static-linking setup needs them.
    for token in libs.split_whitespace() {
        if let Some(name) = token.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={name}");
        } else if let Some(path) = token.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        }
    }

    println!("cargo:rustc-cfg=dpdk_bound");
}

/// Runs bindgen over `csrc/wrapper.h`, allowlisting exactly the exported
/// functions the stack calls plus the types they pull in. The allowlist
/// keeps the generated file focused instead of transcribing every DPDK
/// header in the include graph.
#[cfg(target_os = "linux")]
fn generate_bindings(cflags: &str) {
    use std::path::PathBuf;

    let bindings = bindgen::Builder::default()
        .header("csrc/wrapper.h")
        .clang_args(cflags.split_whitespace())
        .allowlist_function("rte_eal_init")
        .allowlist_function("rte_pktmbuf_pool_create")
        .allowlist_function("rte_eth_dev_count_avail")
        .allowlist_function("rte_eth_rx_queue_setup")
        .allowlist_function("rte_eth_tx_queue_setup")
        .allowlist_function("rte_eth_dev_start")
        .allowlist_function("rte_eth_dev_stop")
        .allowlist_function("rte_eth_dev_close")
        .allowlist_function("rte_eth_promiscuous_enable")
        .allowlist_function("rte_eth_macaddr_get")
        .allowlist_function("rte_eal_cleanup")
        .allowlist_function("rte_eal_remote_launch")
        .allowlist_function("rte_eal_wait_lcore")
        .allowlist_function("rte_get_next_lcore")
        .allowlist_function("rte_lcore_count")
        .allowlist_type("rte_mbuf")
        .allowlist_type("rte_mempool")
        .allowlist_type("rte_ether_addr")
        .derive_default(true)
        .generate()
        .expect("bindgen failed to generate DPDK bindings (is libclang installed?)");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out_dir.join("dpdk_bindings.rs"))
        .expect("failed to write dpdk_bindings.rs");
}

/// Build scripts run on the host: bindgen is only a dependency when the
/// host is Linux, so cross-compiling *to* Linux from another OS can't
/// generate bindings.
#[cfg(not(target_os = "linux"))]
fn generate_bindings(_cflags: &str) {
    panic!(
        "cross-compiling to Linux/DPDK from a non-Linux host is not supported by this build \
         script; build inside the devcontainer instead"
    );
}

fn pkg_config_output(args: &[&str]) -> String {
    let output = Command::new("pkg-config")
        .args(args)
        .output()
        .expect("failed to run pkg-config for libdpdk");
    assert!(
        output.status.success(),
        "pkg-config {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("pkg-config output was not valid UTF-8")
}
