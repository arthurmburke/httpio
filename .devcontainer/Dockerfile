# Rust + DPDK development environment.
#
# Debian bookworm ships DPDK 22.11 LTS as distro packages (libdpdk-dev
# provides the headers and the pkg-config file build.rs looks for).
# clang/libclang are needed by bindgen to generate the FFI bindings from
# the installed DPDK headers at build time.
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# nghttp2 (nghttpd), python3, openssl, iproute2: used by scripts/e2e.sh to
# run real HTTP/1.1 and HTTP/2 TLS servers against the stack over a
# net_tap vdev.
RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
        libdpdk-dev \
        dpdk \
        pkg-config \
        clang \
        libclang-dev \
        nghttp2 \
        iproute2 \
        openssl \
        python3 \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
