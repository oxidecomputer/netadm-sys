// Copyright 2021 Oxide Computer Company
use anyhow::Result;

#[test]
fn get_links() -> Result<()> {

    // just making sure it runs without error
    crate::get_links()?;

    Ok(())
}

#[test]
fn link_consistency() -> Result<()> {

    // just making sure it runs without error
    let links = crate::get_links()?;

    for link in links {
        let same_link = crate::get_link(link.id)?;
        assert_eq!(link, same_link);
    }

    Ok(())
}
