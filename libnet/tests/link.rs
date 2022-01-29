// Copyright 2021 Oxide Computer Company
use anyhow::Result;
use libnet::{
    connect_simnet_peers, create_simnet_link, delete_link, get_link, get_links,
    Error, LinkFlags, LinkHandle, LinkInfo,
};

/// The tests in this file test layer-2 functionality in libnet.
///
/// Most tests need to be run as a user with administrative privileges.
///
/// Conventions:
///   - When a link is created for testing purposes it is prefixed with
///     "lnt_<prefix>" where prefix is unique to the test that is running. This
///     is so test can be run concurrently with out name collisions.

struct DropLink {
    info: LinkInfo,
}
impl DropLink {
    fn handle(&self) -> LinkHandle {
        self.info.handle()
    }
    fn update(&mut self) -> Result<(), Error> {
        self.info.update()
    }
}
impl Drop for DropLink {
    fn drop(&mut self) {
        if let Err(e) = delete_link(&self.info.handle(), self.info.flags) {
            println!("deleting {} failed: {}", self.info.name, e);
        }
    }
}
impl From<LinkInfo> for DropLink {
    fn from(info: LinkInfo) -> Self {
        Self { info }
    }
}

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
    let create_info = create_simnet_link(name, flags).expect("create link");

    // ask for the link we just created
    let get_info = get_link(&handle).expect("get link");
    assert_eq!(create_info, get_info);

    // delete the link
    delete_link(&handle, flags).expect("delete link");

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
