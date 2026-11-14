#!/usr/bin/env bash
set -euo pipefail

rustc=$1
shift

# The build script sees this marker only when built through this workspace
# wrapper. It checks the target, profile and libdpdk before emitting the cfg.
export HTTPIO_DPDK_RUSTC_WRAPPER=1

for arg in "$@"; do
    if [[ "$arg" == dpdk_linker_lto ]]; then
        target_libdir=$("$rustc" --print target-libdir)
        lld="$target_libdir/../bin/gcc-ld/ld.lld"
        # Cargo already builds release Rust dependencies with bitcode for
        # the fat-LTO profile. Let LLD do the final ThinLTO link with C.
        exec "$rustc" "$@" -Clto=off -Clinker-plugin-lto -Clinker=clang "-Clink-arg=--ld-path=$lld"
    fi
done

exec "$rustc" "$@"
