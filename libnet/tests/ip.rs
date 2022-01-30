use anyhow::Result;
use libnet::{
    create_ipaddr, create_simnet_link, enable_v6_link_local, get_ipaddr_info,
    get_ipaddrs, DropIp, DropLink, IpPrefix, Ipv6Prefix, LinkFlags,
};
use std::net::IpAddr;
use std::str::FromStr;

/// The tests in this file test IP address functionality in libnet.
///
/// Most tests need to be run as a user with administrative privileges.
///
/// Conventions:
///
///   - When a link is created for testing purposes it is prefixed with
///     "lnt_<token>" where token is unique to the test that is running. This
///     is so tests can be run concurrently with out name collisions. And so we
///     avoid race conditions between tests in certain situations.
///
///   - When an IP address is created for testing purposes, it takes the form
///     <ifxname>/<token>_lnt, where token is unique to the test that is
///     running.
///
///   - All links should be created using the DropLink type. This is to ensure
///     tests that fail do not leave test links behind on the system.

// Basic Tests ================================================================

/// Call get addresses to make sure it does not error out.
#[test]
fn test_get_addresses() -> Result<()> {
    // just making sure it runs without error
    get_ipaddrs().expect("get links");

    Ok(())
}

/// Test that the addresses we get through iteration are the same addresses we
/// get when requesting an address by a handle.
#[test]
fn test_address_consistency() -> Result<()> {
    let addrs = get_ipaddrs().expect("get addresses");

    for (_, link_addrs) in addrs {
        for addr in link_addrs {
            let (name, _) = addr.obj().expect("address name");

            // Skip over addresses being manipulated in parallel by other tests.
            // This can cause a race condition where we read an address in the
            // get_ipaddrs call above and it has changed by the time we make the
            // comparison below.  This test assumes there is no other active
            // network configuration going on while the test is being run.
            if name.ends_with("lnt") {
                continue;
            }
            // skip simnet interfaces as they are likely from other tests and
            // may change out from under us.
            if name.contains("sim") {
                continue;
            }
            // this can happen due to races with other tests
            if name == "" {
                continue;
            }

            let same_addr = get_ipaddr_info(&name).expect("get addr");
            assert_eq!(addr, same_addr);
        }
    }

    Ok(())
}

// IPv6 Tests =================================================================

/// Add and destory an IPv6 static address
#[test]
fn test_v6_static_lifecycle() -> Result<()> {
    let name = "lo0/v6slnt";
    let prefix =
        Ipv6Prefix::from_str("fd00:1701:d::1/64").expect("parse prefix");

    // create a static address on the loopback device
    create_ipaddr(name, IpPrefix::V6(prefix)).expect("create addr");

    // get the address we just created and chekc equivalence
    let addr: DropIp = get_ipaddr_info(name).expect("get info").into();
    assert_eq!(addr.info.addr, prefix.addr);

    Ok(())
}

/// Add and destory an IPv6 link-local address
#[test]
fn test_v6_local_lifecycle() -> Result<()> {
    let sim0: DropLink = create_simnet_link("lnt_v6ls_sim3", LinkFlags::Active)
        .expect("create sim0")
        .into();

    // enable link-local
    enable_v6_link_local("lnt_v6ls_sim3").expect("enable link local");

    // ask for address we just created and check equivalence
    let addr: DropIp = get_ipaddr_info("lnt_v6ls_sim3/v6")
        .expect("get info")
        .into();

    match addr.info.addr {
        IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0xfe80),
        _ => panic!("not a v6 addr"),
    }
    assert_eq!(10, addr.info.mask as u32);

    drop(addr);

    get_ipaddr_info("lnt_v6ls_sim3/v6").expect_err("zombie addr");

    drop(sim0);

    Ok(())
}
