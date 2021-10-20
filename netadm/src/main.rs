// Copyright 2021 Oxide Computer Company

use anyhow::{anyhow, Result};
use clap::{AppSettings, Clap};
use colored::*;
use netadm_sys::{
    self,
    create_simnet_link,
    create_vnic_link,
    create_ipaddr,
    get_ipaddrs,
    get_link,
    get_links,
    ip,
    route,
    IpState,
    LinkFlags,
    LinkHandle,
    IpPrefix,
};
use std::io::{stdout, Write};
use std::net::IpAddr;
use std::str;
use tabwriter::TabWriter;
use tracing::error;
use tracing_subscriber::{self, EnvFilter};

#[derive(Clap)]
#[clap(
    version = "0.1",
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    #[clap(about = "show things")]
    Show(Show),
    #[clap(about = "create things")]
    Create(Create),
    #[clap(about = "delete things")]
    Delete(Delete),
    #[clap(about = "connect two simnet peers")]
    Connect(SimnetConnect),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Show {
    #[clap(subcommand)]
    subcmd: ShowSubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Create {
    #[clap(subcommand)]
    subcmd: CreateSubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Delete {
    #[clap(subcommand)]
    subcmd: DeleteSubCommand,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct SimnetConnect {
    #[clap(about = "simnet link-id or name")]
    sim_a: LinkHandle,
    #[clap(about = "simnet link-id or name")]
    sim_b: LinkHandle,
}

#[derive(Clap)]
enum ShowSubCommand {
    #[clap(about = "show link-layer interfaces")]
    Links(ShowLinks),
    #[clap(about = "show network-layer addresses")]
    Addrs(ShowAddrs),
    #[clap(about = "show routes")]
    Routes(ShowRoutes),
}

#[derive(Clap)]
enum CreateSubCommand {
    #[clap(about = "create a simnet interface")]
    Simnet(CreateSimnet),
    #[clap(about = "create a vnic interface")]
    Vnic(CreateVnic),
    #[clap(about = "create an ip address")]
    Addr(CreateAddr),
}

#[derive(Clap)]
enum DeleteSubCommand {
    #[clap(about = "delete a link-layer interface")]
    Link(DeleteLink),
    #[clap(about = "delete an ip address")]
    Addr(DeleteAddr),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct CreateSimnet {
    #[clap(about = "name for the new link")]
    name: String,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct CreateVnic {
    #[clap(about = "name for the new link")]
    name: String,
    #[clap(about = "simnet link-id or name")]
    link: LinkHandle,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct CreateAddr {
    #[clap(about = "name for the new address")]
    name: String,
    #[clap(about = "address to create")]
    addr: IpPrefix,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct DeleteLink {
    #[clap(about = "link-id or name")]
    handle: LinkHandle,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct DeleteAddr {
    #[clap(about = "address name")]
    name: String,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct ShowLinks {}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct ShowAddrs {}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct ShowRoutes {}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .compact()
        .init();

    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Show(ref s) => match s.subcmd {
            ShowSubCommand::Links(ref l) => match show_links(&opts, &s, &l) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Addrs(ref a) => match show_addrs(&opts, &s, &a) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Routes(ref r) => match show_routes(&opts, &s, &r) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
        },
        SubCommand::Create(ref c) => match c.subcmd {
            CreateSubCommand::Simnet(ref sim) => match create_simnet(
                &opts, &c, &sim) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            CreateSubCommand::Vnic(ref vnic) => match create_vnic(
                &opts, &c, &vnic) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            CreateSubCommand::Addr(ref addr) => match create_addr(
                &opts, &c, &addr) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
        },
        SubCommand::Delete(ref d) => match d.subcmd {
            DeleteSubCommand::Link(ref lnk) => match delete_link(
                &opts, &d, &lnk) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            DeleteSubCommand::Addr(ref addr) => match delete_addr(
                &opts, &d, &addr) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
        },
        SubCommand::Connect(ref c) => match connect_simnet_peers(&opts, &c) {
            Ok(()) => {}
            Err(e) => error!("{}", e),
        },
    }
}

fn connect_simnet_peers(_opts: &Opts, c: &SimnetConnect) -> Result<()> {
    Ok(netadm_sys::connect_simnet_peers(&c.sim_a, &c.sim_b)?)
}

fn delete_link(_opts: &Opts, _d: &Delete, l: &DeleteLink) -> Result<()> {
    Ok(netadm_sys::delete_link(&l.handle, LinkFlags::Active)?)
}

fn delete_addr(_opts: &Opts, _d: &Delete, a: &DeleteAddr) -> Result<()> {
    Ok(netadm_sys::delete_ipaddr(&a.name)?)
}

fn create_simnet(_opts: &Opts, _c: &Create, s: &CreateSimnet) -> Result<()> {
    create_simnet_link(&s.name, LinkFlags::Active)?;
    // should we print back?
    Ok(())
}

fn create_vnic(_opts: &Opts, _c: &Create, s: &CreateVnic) -> Result<()> {
    create_vnic_link(&s.name, &s.link, LinkFlags::Active)?;
    // should we print back?
    Ok(())
}

fn create_addr(_opts: &Opts, _c: &Create, c: &CreateAddr) -> Result<()> {
    create_ipaddr(&c.name, c.addr)?;
    // should we print back?
    Ok(())
}

fn show_links(_opts: &Opts, _s: &Show, _l: &ShowLinks) -> Result<()> {
    let mut tw = TabWriter::new(stdout());

    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        "Id".dimmed(),
        "Name".dimmed(),
        "Flags".dimmed(),
        "Class".dimmed(),
        "State".dimmed(),
        "MAC".dimmed(),
    )?;
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        "--".bright_black(),
        "----".bright_black(),
        "-----".bright_black(),
        "-----".bright_black(),
        "-----".bright_black(),
        "---".bright_black(),
    )?;

    let links = get_links()?;
    for l in links.iter() {
        let mut name = l.name.clone();
        if l.over != 0 {
            match get_link(l.over) {
                Ok(info) => {
                    name = format!("{}{}{}", name, "|".bright_black(), info.name.bright_black(),);
                }
                _ => {}
            }
        }

        let macf = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            l.mac[0], l.mac[1], l.mac[2], l.mac[3], l.mac[4], l.mac[5],
        );

        write!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            l.id, name, l.flags, l.class, l.state, macf,
        )?;
    }
    tw.flush()?;

    Ok(())
}

fn show_addrs(_opts: &Opts, _s: &Show, _a: &ShowAddrs) -> Result<()> {
    let mut tw = TabWriter::new(stdout());
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\n",
        "Name".dimmed(),
        "Type".dimmed(),
        "State".dimmed(),
        "Address".dimmed(),
        "Interface Index".dimmed(),
    )?;
    write!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\n",
        "--".bright_black(),
        "------".bright_black(),
        "-----".bright_black(),
        "----".bright_black(),
        "---------------".bright_black(),
    )?;

    let addrs = get_ipaddrs()?;

    for (ifx, addrs) in addrs {
        for addr in &addrs {
            let (addrobj, src) =
                ip::ifname_to_addrobj(
                    ifx.as_str(), addr.family).map_err(|e| anyhow!("{}", e))?;

            //TODO gross get an enum
            if src == "none" {
                continue;
            }

            write!(
                &mut tw,
                "{}\t{}\t{}\t{}/{}\t{}\n",
                addrobj,
                src,
                color_state(&addr.state),
                color_ip(addr.addr),
                addr.mask,
                addr.index,
            )?;
        }
    }

    tw.flush()?;

    Ok(())
}

fn show_routes(_opts: &Opts, _s: &Show, _r: &ShowRoutes) -> Result<()> {
    let routes = route::get_routes()?;

    let mut tw = TabWriter::new(stdout());
    write!(
        &mut tw,
        "{}\t{}\n",
        "Destination".dimmed(),
        "Gateway".dimmed(),
    )?;
    write!(
        &mut tw,
        "{}\t{}\n",
        "-----------".bright_black(),
        "-------".bright_black(),
    )?;

    for r in routes.iter() {
        write!(
            &mut tw,
            "{}/{}\t{}\n",
            color_ip(r.dest),
            r.mask,
            color_ip(r.gw),
        )?;
    }

    tw.flush()?;

    Ok(())
}

fn color_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{}", ip.to_string().magenta()),
        IpAddr::V6(_) => format!("{}", ip.to_string().cyan()),
    }
}

fn color_state(state: &IpState) -> String {
    match state {
        IpState::Disabled => format!("{}", "disabled".to_string().bright_black()),
        IpState::Duplicate => format!("{}", "duplicate".to_string().red()),
        IpState::Down => format!("{}", "down".to_string().bright_red()),
        IpState::Tentative => format!("{}", "tentative".to_string().bright_yellow()),
        IpState::OK => format!("{}", "ok".to_string().bright_green()),
        IpState::Inaccessible => format!("{}", "inaccessible".to_string().red()),
    }
}
