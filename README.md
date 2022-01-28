# A Network Administration Crate for Illumos

While the end goal of this crate is to become a stable API for all things
networking on illumos, right now it is the opposite of that. It's as much of an
exploration of the networking subsystems on illumos and how they can be
controlled programmatically from user space as it is an abstraction for other
Rust-based systems to use. In the near to mid term this crate will be highly
unstable.

**Update:** the direction for this crate is starting to take shape, and is
described below.

# Direction

## Where things are at today

Currently, the primary entry points to programmatic access and control of network
configuration and state are `libdladm` and `libipadm`. However, these are both
private libraries, are are more extensions of the programs `dladm` and `ipadm`
than they are libraries. Moreover, their interfaces are considered private, do
not provide stability guarantees and are not meant for general consumption. This
is not a great place to be. Programs running on illumos that need to observe and
control network state and configuration have no good option.

```
           L3:
           /etc/ipadm/*
           /etc/svc/volatile/ipadm/*

           L2:
           /etc/dladm/*
           /etc/svc/volatile/dladm/*

          ┌─────────┐┌─────────┐┌──────┐
          │ dlmgmtd ││ ipmgmtd ││ ndpd │
          └─────────┘└─────────┘└──────┘
┌───────┐ ┌ ─ ─ ─ ─ ┐┌ ─ ─ ─ ─ ─ ─ ─ ─ ┐ ┌───────┐
│ dladm │─ libdladm       libipadm      ─│ ipadm │
└───────┘ └ ─ ─ ─ ─ ┘└ ─ ─ ─ ─ ─ ─ ─ ─ ┘ └───────┘
          ┌────────────────────────────┐
          │           ioctl            │
          └────────────────────────────┘
```

Active network state is kept track of both in the kernel and in user space
daemons. Persistent state is managed exclusively by daemons. The `libdladm` and
`libipadm` libraries manage active state in the kernel through `ioctl` calls and
`kstat` interfaces - and a combination of active and persistent state is managed
via various daemons through either doors invocations or Unix domain sockets from
what I have seen so far. Active state in user space is tracked in
`/etc/svc/volatile/XXXadm/*` files and persistent state is tracked in
`/etc/XXXadm/*` files.

The following is a two phase proposal to establish a stable network API on
illumos.

## Moving forward

### Phase 1

The first phase involves establishing the API and it's underlying implementation
in `libnet`. In this phase `libnet` will be developed to support several
applications simultaneously. This is to get away from the idea that the library
exists to support a CLI administrative client. There are several high value
targets to support under development at Oxide, some of which are shown in the
diagram below. Of course, there will still be an admin CLI `netadm` but this is
not the primary concern.

```
            L3:
            /etc/ipadm/*
            /etc/svc/volatile/ipadm/*

            L2:
            /etc/dladm/*
            /etc/svc/volatile/dladm/*

           ┌─────────┐┌─────────┐┌──────┐   ┌──────────┐
           │ dlmgmtd ││ ipmgmtd ││ ndpd │ ┌─│sled-agent│
           └─────────┘└─────────┘└──────┘ │ └──────────┘
┌────────┐ ┌────────────────────────────┐ │ ┌──────────┐
│ netadm │─│           libnet           │─┼─│  falcon  │
└────────┘ └────────────────────────────┘ │ └──────────┘
           ┌────────────────────────────┐ │ ┌──────────┐
           │           ioctl            │ └─│ propolis │
           └────────────────────────────┘   └──────────┘
```

The interfaces to other parts of the system will remain the same - as painful as
that may be. `libnet` will use the doors-based interfaces for `dlmgmtd` and
`ipmgmtd`, the Unix domain socket interface for `ndpd` and any other interfaces
we come across that are needed to implement an API that satisfies the needs of
our initial set of clients. Although this is the first of two phases, support
for the `libnet` product in this phase is anticipated for an LTS period of
around 4 years, where `libnet`-based tools can coexist with tools and libraries of
today.

`libnet` will be implemented purely as a Rust library. There will be no active
daemon component. Applications will use `libnet` by consuming the library
interfaces directly from their own code.

### Phase 2

```
                                            ┌──────────┐
                                          ┌─│ netinit  │
            L3:                           │ └──────────┘
            /etc/ipadm/*                  │ ┌──────────┐
            /etc/svc/volatile/ipadm/*     ├─│  dhcpd   │
                                          │ └──────────┘
            L2:                           │ ┌──────────┐
            /etc/dladm/*                  ├─│   ndpd   │
            /etc/svc/volatile/dladm/*     │ └──────────┘
                                          │ ┌──────────┐
┌────────┐ ┌────────────────────────────┐ ├─│sled-agent│
│ netadm │─│           libnet           │─┤ └──────────┘
└────────┘ └────────────────────────────┘ │ ┌──────────┐
           ┌────────────────────────────┐ ├─│  falcon  │
           │           ioctl            │ │ └──────────┘
           └────────────────────────────┘ │ ┌──────────┐
                                          └─│ propolis │
                                            └──────────┘
```

Phase will begin right after phase 1 has produced a stable API and will be a
concurrent effort with maintaining and supporting the phase 1 `libnet` product.

Phase 2 subsumes the functions of the existing network daemons into the library,
managing persistent and active state directly. The goal here is to create a
common mechanism for applications and daemons to produce and consume network
state system wide - and for that mechanism to lend itself to statically
verifiable correctness properties. In this phase `libnet` will implement IPC
synchronization mechanisms under the hood to ensure that concurrent API calls
over common state do not cause corruption or undefined results.

In this model all state has a single owner, `libnet`.  This may seem like
perilous centralization, however, it's really more about creating a standard set
of rules and mechanisms for interacting with network state and configuration. In
fact, the opportunity for distribution increases with `libnet` phase 2, as the
small collection of centralized deamons gives way to to a library built to
support decentralized and distributed participants that coordinate through IPC
synchronization primitives without any active centralized entity.

## Contributing

### Basic Checks

```
cargo fmt -- --check
cargo clippy
```

### Testing

```
cargo test
```
