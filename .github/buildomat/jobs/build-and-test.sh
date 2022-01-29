#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly-2021-09-03"
#: output_rules = [
#:   "target/debug/netadm",
#:   "target/release/netadm",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build
ptime -m cargo build
ptime -m cargo build --release

banner check
cargo fmt -- --check
cargo clippy

banner pre-test
uname -a
./target/debug/netadm show links
./target/debug/netadm show addrs

banner test
pfexec ptime -m cargo test

banner post-test
./target/debug/netadm show links
./target/debug/netadm show addrs
