// Copyright 2021 Oxide Computer Company

use anyhow::{anyhow, Result};
use clap::{AppSettings, Parser};
use colored::*;
use netadm_sys::{
    self, add_route, create_ipaddr, create_simnet_link, create_vnic_link,
    get_ipaddr_info, get_ipaddrs, get_link, get_links, ip, route, IpPrefix,
    IpState, LinkFlags, LinkHandle,
};
use std::io::{stdout, Write};
use std::net::IpAddr;
use std::str;
use tabwriter::TabWriter;
use tracing::error;
use tracing_subscriber::{self, EnvFilter};

#[derive(Parser)]
#[clap(
    version = "0.1",
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>"
)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    #[clap(about = "show things")]
    Show(Show),
    #[clap(about = "create things")]
    Create(Create),
    #[clap(about = "delete things")]
    Delete(Delete),
    #[clap(about = "enable things")]
    Enable(Enable),
    #[clap(about = "connect two simnet peers")]
    Connect(SimnetConnect),
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Show {
    #[clap(subcommand)]
    subcmd: ShowSubCommand,
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Create {
    #[clap(subcommand)]
    subcmd: CreateSubCommand,
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Enable {
    #[clap(subcommand)]
    subcmd: EnableSubCommand,
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Delete {
    #[clap(subcommand)]
    subcmd: DeleteSubCommand,
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct SimnetConnect {
    #[clap(about = "simnet link-id or name")]
    sim_a: LinkHandle,
    #[clap(about = "simnet link-id or name")]
    sim_b: LinkHandle,
}

#[derive(Parser)]
enum ShowSubCommand {
    #[clap(about = "show link-layer interfaces")]
    Links(ShowLinks),
    #[clap(about = "show network-layer addresses")]
    Addrs(ShowAddrs),
    #[clap(about = "show routes")]
    Routes(ShowRoutes),
}

#[derive(Parser)]
enum CreateSubCommand {
    #[clap(about = "create a simnet interface")]
    Simnet(CreateSimnet),
    #[clap(about = "create a vnic interface")]
    Vnic(CreateVnic),
    #[clap(about = "create an ip address")]
    Addr(CreateAddr),
    #[clap(about = "create a route")]
    Route(CreateRoute),
}

#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
enum EnableSubCommand {
    #[clap(about = "Enable IPv4 network functions")]
    V4(EnableV4Subcommand),
    #[clap(about = "Enable IPv6 network functions")]
    V6(EnableV6Subcommand),
}

/// Enable IPv6 network functions.
#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct EnableV6Subcommand {
    #[clap(about = "available functions: link-local (or ll), or dhcp")]
    function: V6Function,
    #[clap(about = "interface name")]
    interface: String,
}

/// Enable IPv4 network functions.
#[derive(Parser)]
#[clap(setting = AppSettings::InferSubcommands)]
struct EnableV4Subcommand {
    #[clap(about = "available functions: dhcp")]
    function: V4Function,
    #[clap(about = "interface name")]
    interface: String,
}

#[derive(Parser)]
enum V6Function {
    LinkLocal,
    Dhcp,
}

impl std::str::FromStr for V6Function {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "link-local" => Ok(V6Function::LinkLocal),
            "ll" => Ok(V6Function::LinkLocal),
            "dhcp" => Ok(V6Function::Dhcp),
            _ => Err(anyhow!("V6 function must be link-local, ll or dhcp")),
        }
    }
}

impl std::str::FromStr for V4Function {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dhcp" => Ok(V4Function::Dhcp),
            _ => Err(anyhow!("V4 function must be dhcp")),
        }
    }
}

#[derive(Parser)]
enum V4Function {
    Dhcp,
}

#[derive(Parser)]
enum DeleteSubCommand {
    #[clap(about = "delete a link-layer interface")]
    Link(DeleteLink),
    #[clap(about = "delete an ip address")]
    Addr(DeleteAddr),
    #[clap(about = "delete a route")]
    Route(DeleteRoute),
}

#[derive(Parser)]
struct CreateSimnet {
    #[clap(about = "name for the new link")]
    name: String,
}

#[derive(Parser)]
struct CreateVnic {
    #[clap(about = "name for the new link")]
    name: String,
    #[clap(about = "simnet link-id or name")]
    link: LinkHandle,
}

#[derive(Parser)]
struct CreateAddr {
    #[clap(about = "name for the new address")]
    name: String,
    #[clap(about = "address to create")]
    addr: IpPrefix,
}

#[derive(Parser)]
struct CreateRoute {
    #[clap(about = "route destination")]
    destination: IpPrefix,
    #[clap(about = "route gateway")]
    gateway: IpAddr,
}

#[derive(Parser)]
struct DeleteRoute {
    #[clap(about = "route destination")]
    destination: IpPrefix,
    #[clap(about = "route gateway")]
    gateway: IpAddr,
}

#[derive(Parser)]
struct DeleteLink {
    #[clap(about = "link-id or name")]
    handle: LinkHandle,
}

#[derive(Parser)]
struct DeleteAddr {
    #[clap(about = "address name")]
    name: String,
}

#[derive(Parser)]
struct ShowLinks {}

#[derive(Parser)]
struct ShowAddrs {
    #[clap(short, long, about = "restrict to the provided interface name")]
    name: Option<String>,
}

#[derive(Parser)]
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
            CreateSubCommand::Simnet(ref sim) => {
                match create_simnet(&opts, &c, &sim) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Vnic(ref vnic) => {
                match create_vnic(&opts, &c, &vnic) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Addr(ref addr) => {
                match create_addr(&opts, &c, &addr) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Route(ref route) => {
                match create_route(&opts, &c, &route) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
        },
        SubCommand::Delete(ref d) => match d.subcmd {
            DeleteSubCommand::Link(ref lnk) => {
                match delete_link(&opts, &d, &lnk) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            DeleteSubCommand::Addr(ref addr) => {
                match delete_addr(&opts, &d, &addr) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            DeleteSubCommand::Route(ref route) => {
                match delete_route(&opts, &d, &route) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
        },
        SubCommand::Enable(ref e) => match e.subcmd {
            EnableSubCommand::V4(ref cmd) => {
                match enable_v4_function(&opts, &e, &cmd) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            EnableSubCommand::V6(ref cmd) => {
                match enable_v6_function(&opts, &e, &cmd) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
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

fn create_route(_opts: &Opts, _c: &Create, c: &CreateRoute) -> Result<()> {
    add_route(c.destination, c.gateway)?;
    // should we print back?
    Ok(())
}

fn delete_route(_opts: &Opts, _c: &Delete, c: &DeleteRoute) -> Result<()> {
    netadm_sys::delete_route(c.destination, c.gateway)?;
    // should we print back?
    Ok(())
}

fn enable_v4_function(
    _opts: &Opts,
    _c: &Enable,
    _cmd: &EnableV4Subcommand,
) -> Result<()> {
    todo!();
}

fn enable_v6_function(
    _opts: &Opts,
    _c: &Enable,
    cmd: &EnableV6Subcommand,
) -> Result<()> {
    netadm_sys::enable_v6_link_local(&cmd.interface)?;
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
                    name = format!(
                        "{}{}{}",
                        name,
                        "|".bright_black(),
                        info.name.bright_black(),
                    );
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

fn show_addrs(_opts: &Opts, _s: &Show, a: &ShowAddrs) -> Result<()> {
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

    if a.name.is_some() {
        let name = a.name.as_ref().unwrap();

        let addr = get_ipaddr_info(name).map_err(|e| anyhow!("{}", e))?;

        let (addrobj, src, _, _, _) =
            ip::addrobjname_to_addrobj(name).map_err(|e| anyhow!("{}", e))?;
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
        tw.flush()?;

        return Ok(());
    }

    let addrs = get_ipaddrs()?;

    for (ifx, addrs) in addrs {
        for addr in &addrs {
            let (addrobj, src) =
                ip::ifname_to_addrobj(ifx.as_str(), addr.family)
                    .map_err(|e| anyhow!("{}", e))?;

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
        IpState::Disabled => {
            format!("{}", "disabled".to_string().bright_black())
        }
        IpState::Duplicate => format!("{}", "duplicate".to_string().red()),
        IpState::Down => format!("{}", "down".to_string().bright_red()),
        IpState::Tentative => {
            format!("{}", "tentative".to_string().bright_yellow())
        }
        IpState::OK => format!("{}", "ok".to_string().bright_green()),
        IpState::Inaccessible => {
            format!("{}", "inaccessible".to_string().red())
        }
    }
}
