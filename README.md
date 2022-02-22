# A Network Administration Crate for Illumos

- [Documentation](https://oxidecomputer.github.io/netadm-sys/libnet/index.html)

While the end goal of this crate is to become a stable API for all things
networking on illumos, right now it is the opposite of that. It's as much of an
exploration of the networking subsystems on illumos and how they can be
controlled programmatically from user space as it is an abstraction for other
Rust-based systems to use. In the near to mid term this crate will be highly
unstable.

## Contributing

### Basic Checks

```
cargo fmt -- --check
cargo clippy
```

### Testing

```
pfexec cargo test
```
