# bpf-hole

## what am I looking at?

This attempts to reimplement pi-hole dns block as an eBPF program. It's doing packet inspection on udp traffic via TC (traffic / transmission control). If a `bad` hostname is detected, it will redirect the packet to localhost.
It then uses a `XDP` program to drop the traffic of the redirected packet. Technically the XDP part is not necessary because we could stop the packet to ever egress the interface within the TC context. But this way we have been able to also try routing via eBPF.

## Why?

To understand eBPF and what it can do or won't. I don't think DNS packet inspection is a great usecase, but it is one that I can use to understand
how to write eBPF programs. This should probably not be running on anyones system but if you're feeling adventurous: `gl & hf` (You could just put a static hosts config on your system instead).

But that's no fun is it.

## Run it?
export BPF_HOLE_IFACE=< your interface of choice for filtering packets >
if you're using `nix`:

start bpf-hole
```shell
nix run
```

additional nix helpers:

```shell
# dump loopback iface to debug the redirected dns requests
nix run .#dump_lo

```

## known limitations

### no support for filtering dnsoverhttps
it seems to be possible to do this though. We do not even need to care about decrypting the traffic:

see: https://github.com/gojue/ecapture


### no support for filtering ipv6 dns packets.

if using nslookup / dig eventually it will resolve because there seems to be a fallback to ipv6 in dig/nslookup:
```
nslookup metric.zzzquil.com
;; communications error to XXX.XXX.CCC.1#53: timed out
;; communications error to XXX.XXX.CCC.1#53: timed out
;; communications error to XXX.XXX.CCC.1#53: timed out
Server:         fdca:XXXX:XXXX:X:XXXX:XXXX:XXXX:79f4
Address:        fdca:XXXX:XXXX:X:XXXX:XXXX:XXXX:79f4#53

Non-authoritative answer:
metric.zzzquil.com      canonical name = zzzquil-en-us-redesign.azureedge.net.
zzzquil-en-us-redesign.azureedge.net    canonical name = zzzquil-en-us-redesign.afd.azureedge.net.
zzzquil-en-us-redesign.afd.azureedge.net        canonical name = azureedge-t-prod.trafficmanager.net.
azureedge-t-prod.trafficmanager.net     canonical name = shed.dual-low.s-part-0017.t-0009.t-msedge.net.
shed.dual-low.s-part-0017.t-0009.t-msedge.net   canonical name = azurefd-t-fb-prod.trafficmanager.net.
azurefd-t-fb-prod.trafficmanager.net    canonical name = dual.s-part-0017.t-0009.fb-t-msedge.net.
dual.s-part-0017.t-0009.fb-t-msedge.net canonical name = s-part-0017.t-0009.fb-t-msedge.net.
Name:   s-part-0017.t-0009.fb-t-msedge.net
Address: 13.107.253.45
Name:   s-part-0017.t-0009.fb-t-msedge.net
Address: 2620:1ec:29:1::45

```

there's a high chance the same will happen in the browser.

# the below are the auto generated docs by the aya template and will tell you how to run with your system rust.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package bpf-hole --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/bpf-hole` can be
copied to a Linux server or VM and run there.
