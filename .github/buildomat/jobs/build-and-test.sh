#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
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

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/netadm /work/$x/netadm
done

banner check
cargo fmt -- --check
cargo clippy --all-targets -- --deny warnings

banner pre-test
uname -a
./target/debug/netadm show links
./target/debug/netadm show addrs

banner test
pfexec ptime -m cargo test
pfexec ptime -m cargo test --release

banner post-test
./target/debug/netadm show links
./target/debug/netadm show addrs
