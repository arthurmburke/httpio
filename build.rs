//! Generates the DPDK FFI at build time and links against libdpdk.
//!
//! Everything is generated -- there is no hand-written C shim. bindgen's
//! `wrap_static_fns` emits a C file with real wrapper functions for DPDK's
//! `static inline` hot-path (`rte_pktmbuf_alloc`, `rte_eth_rx_burst`, ...),
//! which are otherwise unreachable from Rust because they have no linkable
//! symbol. We compile that generated C and link it alongside the bindings.
//!
//! libdpdk availability is detected automatically: this script probes
//! pkg-config for it and, when found, sets the `dpdk` cfg and generates +
//! links the FFI. When it's absent (e.g. on macOS) the script is a near
//! no-op, the `dpdk` cfg stays unset, and the `dpdk` module and its binaries
//! are compiled out -- leaving just `core` + the `http` traits, which need
//! no native libraries. Build the DPDK stack in the devcontainer.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    // `dpdk` is a build-script-set cfg (not a Cargo feature); declare it so
    // the unexpected_cfgs lint knows it's expected whether or not it's set.
    println!("cargo::rustc-check-cfg=cfg(dpdk)");

    // Locate libdpdk and emit its link flags (this also prints the
    // cargo:rustc-link-lib/search lines for every DPDK library). If it isn't
    // installed, build the rest of the crate without the DPDK stack rather
    // than failing.
    let Ok(dpdk) = pkg_config::Config::new().statik(false).probe("libdpdk") else {
        println!(
            "cargo::warning=libdpdk not found via pkg-config; building without the DPDK stack \
             (core + http traits only). Install the DPDK dev packages (e.g. \
             `apt install libdpdk-dev`) or set PKG_CONFIG_PATH to build it -- the devcontainer \
             has it."
        );
        return;
    };

    // libdpdk is present: turn on the DPDK stack.
    println!("cargo::rustc-cfg=dpdk");

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
