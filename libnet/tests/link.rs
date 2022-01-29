// Copyright 2021 Oxide Computer Company
use anyhow::Result;
use libnet::{
    connect_simnet_peers, create_simnet_link, create_vnic_link, delete_link,
    get_link, get_links, Error, LinkFlags, LinkHandle, LinkInfo,
    DropLink, DropIp,
};

/// The tests in this file test layer-2 functionality in libnet.
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
///   - All links should be created using the DropLink type. This is to ensure
///     tests that fail do not leave test links behind on the system.


// Basic Tests ================================================================

/// Call get links to make sure it does not error out.
#[test]
fn test_get_links() -> Result<()> {
    // just making sure it runs without error
    get_links().expect("get links");

    Ok(())
}

/// Test that the links we get through iteration are the same links we get when
/// requesting a link by a handle.
#[test]
fn test_link_consistency() -> Result<()> {
    let links = get_links().expect("get links");

    for link in links {
        // Skip over links being manipulated in parallel by other tests. This
        // can cause a race condition where we read a link in the get_links call
        // above and it has changed by the time we make the comparison below.
        // This test assumes there is no other active network configuration
        // going on while the test is being run.
        if link.name.starts_with("lnt") {
            continue;
        }
        let handle = LinkHandle::Id(link.id);
        let same_link = get_link(&handle).expect("get link");
        assert_eq!(link, same_link);
    }

    Ok(())
}

// Simnet Tests ===============================================================

/// Create, query and destroy a simnet link
#[test]
fn test_simnet_lifecycle() -> Result<()> {
    let name = "lnt_simlc_sim0";
    let handle = LinkHandle::Name(name.into());
    let flags = LinkFlags::Active;

    // create a simnet link
    let sim0: DropLink =
        create_simnet_link(name, flags).expect("create link").into();

    // ask for the link we just created
    let info = get_link(&handle).expect("get link");
    assert_eq!(sim0.info, info);

    // delete the link
    drop(sim0);

    // make sure the link no longer exists
    get_link(&handle).expect_err("zombie link");

    Ok(())
}

/// Connect simnet links
#[test]
fn test_simnet_connect() -> Result<()> {
    let flags = LinkFlags::Active;

    let mut sim0: DropLink = create_simnet_link("lnt_simc_sim0", flags)
        .expect("create sim0")
        .into();

    let mut sim1: DropLink = create_simnet_link("lnt_simc_sim1", flags)
        .expect("create sim1")
        .into();

    connect_simnet_peers(&sim0.handle(), &sim1.handle()).expect("connect");

    // update the simnet info instances
    sim0.update().expect("update sim0");
    sim1.update().expect("update sim1");

    // ensure the objects are linked
    assert_eq!(sim0.info.over, sim1.info.id);
    assert_eq!(sim1.info.over, sim0.info.id);

    Ok(())
}

// Vnic Tests =================================================================

/// Create, query and destroy a vnic
#[test]
fn test_vnic_lifecycle() -> Result<()> {
    let name = "lnt_vc_vnic0";
    let flags = LinkFlags::Active;

    // first create a simnet link for this vnic to hang off of
    let sim0: DropLink = create_simnet_link("lnt_vc_sim0", flags)
        .expect("create simnet")
        .into();

    // create vnic
    let vnic0: DropLink = create_vnic_link(name, &sim0.handle(), flags)
        .expect("create vnic")
        .into();

    // ask for the vnic we just created
    let info = get_link(&vnic0.handle()).expect("get vnic");
    assert_eq!(vnic0.info, info);
    // ensure the vnic is attached to the simnet link
    assert_eq!(vnic0.info.over, sim0.info.id);

    // delete the vnic
    drop(vnic0);

    // make sure the link no longer exists
    get_link(&LinkHandle::Name(name.into())).expect_err("zombie link");

    Ok(())
}
