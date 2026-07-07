//! Generates the DPDK FFI at build time and links against libdpdk.
//!
//! Everything is generated -- there is no hand-written C shim. bindgen's
//! `wrap_static_fns` emits a C file with real wrapper functions for DPDK's
//! `static inline` hot-path (`rte_pktmbuf_alloc`, `rte_eth_rx_burst`, ...),
//! which are otherwise unreachable from Rust because they have no linkable
//! symbol. We compile that generated C and link it alongside the bindings.
//!
//! DPDK is a hard requirement (Linux-only): this build script always runs
//! bindgen + pkg-config, so `cargo build`/`check` must run where libdpdk is
//! installed -- the devcontainer. There is no non-DPDK fallback.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    // Locate libdpdk and emit its link flags (this also prints the
    // cargo:rustc-link-lib/search lines for every DPDK library).
    let dpdk = pkg_config::Config::new()
        .statik(false)
        .probe("libdpdk")
        .expect(
            "libdpdk not found via pkg-config.\n\
             Install the DPDK dev packages (e.g. `apt install libdpdk-dev`) or set \
             PKG_CONFIG_PATH to a prefix containing libdpdk.pc. Build in the devcontainer.",
        );

    // numa/pthread aren't always pulled in transitively by libdpdk.pc.
    println!("cargo:rustc-link-lib=numa");
    println!("cargo:rustc-link-lib=pthread");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let static_fns_c = out_dir.join("dpdk_static_fns.c");

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .derive_default(true)
        .derive_debug(false)
        .generate_comments(false)
        .prepend_enum_name(false)
        // Emit a C file with wrappers for `static inline` functions so the
        // datapath (rx/tx burst, pktmbuf alloc/free/append, ...) is
        // callable from Rust.
        .wrap_static_fns(true)
        .wrap_static_fns_path(&static_fns_c)
        // Many DPDK constants (e.g. RTE_ETH_TX_OFFLOAD_*_CKSUM) are defined
        // via the RTE_BIT64() function-macro, which bindgen can't
        // constant-fold on its own. This falls back to clang to evaluate
        // them so they're generated rather than hand-transcribed.
        .clang_macro_fallback()
        .allowlist_function("rte_.*")
        .allowlist_type("rte_.*")
        .allowlist_type("RTE_.*")
        .allowlist_var("RTE_.*")
        .allowlist_var("rte_.*")
        // DPDK headers lean on GNU attributes/extensions clang chokes on
        // when reduced to a bindgen parse; neutralize them.
        .clang_arg("-D__attribute__(x)=")
        .clang_arg("-D__extension__=");

    for include in &dpdk.include_paths {
        builder = builder.clang_arg(format!("-I{}", include.display()));
    }

    let bindings = builder
        .generate()
        .expect("bindgen failed to generate DPDK bindings (is libclang installed?)");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    // Compile and link the generated static-inline wrappers.
    let mut cc = cc::Build::new();
    cc.file(&static_fns_c).include(".");
    for include in &dpdk.include_paths {
        cc.include(include);
    }
    for (k, v) in &dpdk.defines {
        match v {
            Some(val) => cc.define(k, val.as_str()),
            None => cc.define(k, None),
        };
    }
    cc.flag_if_supported("-march=native")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-deprecated-declarations")
        // The generated wrappers trip a couple of harmless warnings: our
        // `-D__attribute__(x)=` neutralization turns DPDK's `__rte_const`
        // into a duplicate `const`, and a few internal arch helpers (e.g.
        // `rte_arch_bswap16`) are declared in headers we don't include but
        // are never actually called from Rust.
        .flag_if_supported("-Wno-duplicate-decl-specifier")
        .flag_if_supported("-Wno-implicit-function-declaration")
        .compile("dpdk_static_fns");
}
