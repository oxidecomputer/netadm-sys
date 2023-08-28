// Copyright 2023 Oxide Computer Company

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use libnet::{
    self, add_route, create_ipaddr, create_simnet_link, create_tfport_link,
    create_vnic_link, get_ipaddr_info, get_ipaddrs, get_link, get_links, ip,
    route, sys::MAXMACADDRLEN, IpPrefix, IpState, LinkFlags, LinkHandle,
};
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::str;
use tabwriter::TabWriter;
use tracing::error;
use tracing_subscriber::{self, EnvFilter};

#[derive(Parser)]
#[clap(
    version = "0.1",
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>",
    styles = get_styles()
)]
#[clap(infer_subcommands(true))]
struct Opts {
    #[clap(short, long)]
    verbose: bool,

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
struct Show {
    #[clap(subcommand)]
    subcmd: ShowSubCommand,
}

#[derive(Parser)]
struct Create {
    #[clap(subcommand)]
    subcmd: CreateSubCommand,
}

#[derive(Parser)]
struct Enable {
    #[clap(subcommand)]
    subcmd: EnableSubCommand,
}

#[derive(Parser)]
struct Delete {
    #[clap(subcommand)]
    subcmd: DeleteSubCommand,
}

#[derive(Parser)]
struct SimnetConnect {
    /// Simnet link-id or name
    sim_a: LinkHandle,
    /// Simnet link-id or name
    sim_b: LinkHandle,
}

#[derive(Parser)]
enum ShowSubCommand {
    /// Show link-layer interfaces
    Links(ShowLinks),
    /// Show network-layer addresses
    Addrs(ShowAddrs),
    /// Show routes
    Routes(ShowRoutes),
    /// Show a route
    Route(ShowRoute),
    /// Show neighbor
    Neighbor(ShowNeighbor),
}

#[derive(Parser)]
enum CreateSubCommand {
    /// Create a simnet interface
    Simnet(CreateSimnet),
    /// Create a tfport interface
    Tfport(CreateTfport),
    /// Create a vnic interface
    Vnic(CreateVnic),
    /// Create an ip address
    Addr(CreateAddr),
    /// create a route
    Route(CreateRoute),
}

#[derive(Parser)]
enum EnableSubCommand {
    /// Enable IPv4 network functions
    V4(EnableV4Subcommand),
    /// Enable IPv6 network functions
    V6(EnableV6Subcommand),
}

/// Enable IPv6 network functions.
#[derive(Parser)]
struct EnableV6Subcommand {
    /// Mode
    function: V6Mode,
    /// Interface name
    interface: String,
    /// Address name
    addr_name: String,
}

/// Enable IPv4 network functions.
#[derive(Parser)]
struct EnableV4Subcommand {
    /// Mode
    function: V4Mode,
    /// Interface name
    interface: String,
}

#[derive(Parser, Copy, Clone, ValueEnum)]
enum V6Mode {
    LinkLocal,
    Dhcp,
}

#[derive(Parser, Copy, Clone, ValueEnum)]
enum V4Mode {
    Dhcp,
}

#[derive(Parser)]
enum DeleteSubCommand {
    /// Delete a link-layer interface
    Link(DeleteLink),
    /// Delete an ip address
    Addr(DeleteAddr),
    /// Delete a route
    Route(DeleteRoute),
}

#[derive(Parser)]
struct CreateSimnet {
    /// Name for the new link
    name: String,
}

#[derive(Parser)]
struct CreateTfport {
    /// Name for the new link
    name: String,
    /// Tofino port
    port: u16,
    /// Source of sidecar packets
    over: String,
    /// MAC address for the new link
    mac: Option<String>,
}

#[derive(Parser)]
struct CreateVnic {
    /// Name for the new link
    name: String,
    /// Simnet link-id or name
    link: LinkHandle,
    /// Mac address
    #[clap(short, long)]
    mac: Option<String>,
}

#[derive(Parser)]
struct CreateAddr {
    /// Name for the new address
    name: String,
    /// Address to create
    addr: IpPrefix,
}

#[derive(Parser)]
struct CreateRoute {
    /// Route destination
    destination: IpPrefix,
    /// Route gateway
    gateway: IpAddr,
    /// Route interface
    interface: Option<String>,
}

#[derive(Parser)]
struct DeleteRoute {
    /// Route destination
    destination: IpPrefix,
    /// Route gateway
    gateway: IpAddr,
    /// Route interface
    interface: Option<String>,
}

#[derive(Parser)]
struct DeleteLink {
    /// Link-id or name
    handle: LinkHandle,
}

#[derive(Parser)]
struct DeleteAddr {
    /// Address name
    name: String,
}

#[derive(Parser)]
struct ShowLinks {}

#[derive(Parser)]
struct ShowAddrs {
    /// Restrict to the provided interface name
    #[clap(short, long)]
    name: Option<String>,
}

#[derive(Parser)]
struct ShowRoutes {
    /// Show only IPv6 routes
    #[clap(short = '6')]
    v6_only: bool,

    /// Show only IPv4 routes
    #[clap(short = '4')]
    v4_only: bool,
}

#[derive(Parser)]
struct ShowRoute {
    /// The destination to show a route for.
    destination: IpPrefix,
}

#[derive(Parser)]
struct ShowNeighbor {
    /// Name of the interface
    ifname: String,
    /// IPv6 address to show neighbor for
    addr: Ipv6Addr,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .compact()
        .init();

    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Show(ref s) => match s.subcmd {
            ShowSubCommand::Links(ref l) => match show_links(&opts, s, l) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Addrs(ref a) => match show_addrs(&opts, s, a) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Routes(ref r) => match show_routes(&opts, s, r) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Route(ref r) => match show_a_route(&opts, s, r) {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
            ShowSubCommand::Neighbor(ref n) => match show_neighbor(&opts, s, n)
            {
                Ok(()) => {}
                Err(e) => error!("{}", e),
            },
        },
        SubCommand::Create(ref c) => match c.subcmd {
            CreateSubCommand::Simnet(ref sim) => {
                match create_simnet(&opts, c, sim) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Tfport(ref tfp) => {
                match create_tfport(&opts, c, tfp) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Vnic(ref vnic) => {
                match create_vnic(&opts, c, vnic) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Addr(ref addr) => {
                match create_addr(&opts, c, addr) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            CreateSubCommand::Route(ref route) => {
                match create_route(&opts, c, route) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
        },
        SubCommand::Delete(ref d) => match d.subcmd {
            DeleteSubCommand::Link(ref lnk) => {
                match delete_link(&opts, d, lnk) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            DeleteSubCommand::Addr(ref addr) => {
                match delete_addr(&opts, d, addr) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            DeleteSubCommand::Route(ref route) => {
                match delete_route(&opts, d, route) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
        },
        SubCommand::Enable(ref e) => match e.subcmd {
            EnableSubCommand::V4(ref cmd) => {
                match enable_v4_function(&opts, e, cmd) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
            EnableSubCommand::V6(ref cmd) => {
                match enable_v6_function(&opts, e, cmd) {
                    Ok(()) => {}
                    Err(e) => error!("{}", e),
                }
            }
        },
        SubCommand::Connect(ref c) => match connect_simnet_peers(&opts, c) {
            Ok(()) => {}
            Err(e) => error!("{}", e),
        },
    }
}

fn connect_simnet_peers(_opts: &Opts, c: &SimnetConnect) -> Result<()> {
    Ok(libnet::connect_simnet_peers(&c.sim_a, &c.sim_b)?)
}

fn delete_link(_opts: &Opts, _d: &Delete, l: &DeleteLink) -> Result<()> {
    Ok(libnet::delete_link(&l.handle, LinkFlags::Active)?)
}

fn delete_addr(_opts: &Opts, _d: &Delete, a: &DeleteAddr) -> Result<()> {
    Ok(libnet::delete_ipaddr(&a.name)?)
}

fn create_simnet(_opts: &Opts, _c: &Create, s: &CreateSimnet) -> Result<()> {
    create_simnet_link(&s.name, LinkFlags::Active)?;
    // should we print back?
    Ok(())
}

fn create_tfport(_opts: &Opts, _c: &Create, s: &CreateTfport) -> Result<()> {
    let mac = s.mac.as_ref().map(|m| m.to_string());

    create_tfport_link(&s.name, &s.over, s.port, mac, LinkFlags::Active)?;
    Ok(())
}

fn create_vnic(_opts: &Opts, _c: &Create, s: &CreateVnic) -> Result<()> {
    match &s.mac {
        None => {
            create_vnic_link(&s.name, &s.link, None, LinkFlags::Active)?;
        }
        Some(mac) => {
            let parts: Vec<&str> = mac.split(':').collect();
            if parts.len() > MAXMACADDRLEN as usize {
                return Err(anyhow!(
                    "mac cannot exceed {} bytes",
                    MAXMACADDRLEN
                ));
            }
            let mut m = Vec::new();
            for p in parts {
                let x = u8::from_str_radix(p, 16)?;
                m.push(x)
            }
            create_vnic_link(&s.name, &s.link, Some(m), LinkFlags::Active)?;
        }
    }
    // should we print back?
    Ok(())
}

fn create_addr(_opts: &Opts, _c: &Create, c: &CreateAddr) -> Result<()> {
    create_ipaddr(&c.name, c.addr)?;
    // should we print back?
    Ok(())
}

fn create_route(_opts: &Opts, _c: &Create, c: &CreateRoute) -> Result<()> {
    add_route(c.destination, c.gateway, c.interface.clone())?;
    // should we print back?
    Ok(())
}

fn delete_route(_opts: &Opts, _c: &Delete, c: &DeleteRoute) -> Result<()> {
    libnet::delete_route(c.destination, c.gateway, c.interface.clone())?;
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
    libnet::enable_v6_link_local(&cmd.interface, &cmd.addr_name)?;
    Ok(())
}

fn show_links(_opts: &Opts, _s: &Show, _l: &ShowLinks) -> Result<()> {
    let mut tw = TabWriter::new(stdout());

    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Id".dimmed(),
        "Name".dimmed(),
        "Flags".dimmed(),
        "Class".dimmed(),
        "State".dimmed(),
        "MAC".dimmed(),
        "MTU".dimmed(),
    )?;
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "--".bright_black(),
        "----".bright_black(),
        "-----".bright_black(),
        "-----".bright_black(),
        "-----".bright_black(),
        "---".bright_black(),
        "---".bright_black(),
    )?;

    let links = get_links()?;
    for l in links.iter() {
        let mut name = l.name.clone();
        if l.over != 0 {
            if let Ok(info) = get_link(&LinkHandle::Id(l.over)) {
                name = format!(
                    "{}{}{}",
                    name,
                    "|".bright_black(),
                    info.name.bright_black(),
                );
            }
        }

        let macf = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            l.mac[0], l.mac[1], l.mac[2], l.mac[3], l.mac[4], l.mac[5],
        );

        let mtu = if let Some(mtu) = l.mtu {
            mtu.to_string()
        } else {
            "?".to_string()
        };

        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            l.id, name, l.flags, l.class, l.state, macf, mtu,
        )?;
    }
    tw.flush()?;

    Ok(())
}

fn show_addrs(_opts: &Opts, _s: &Show, a: &ShowAddrs) -> Result<()> {
    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}",
        "Name".dimmed(),
        "Type".dimmed(),
        "State".dimmed(),
        "Address".dimmed(),
        "Interface Index".dimmed(),
    )?;
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}",
        "----".bright_black(),
        "------".bright_black(),
        "-----".bright_black(),
        "-------".bright_black(),
        "---------------".bright_black(),
    )?;

    if a.name.is_some() {
        let name = a.name.as_ref().unwrap();

        let addr = get_ipaddr_info(name).map_err(|e| anyhow!("{}", e))?;

        let (addrobj, src, _, _, _) =
            ip::addrobjname_to_addrobj(name).map_err(|e| anyhow!("{}", e))?;
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}/{}\t{}",
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

            writeln!(
                &mut tw,
                "{}\t{}\t{}\t{}/{}\t{}",
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

fn show_a_route(_opts: &Opts, _s: &Show, sr: &ShowRoute) -> Result<()> {
    let route = route::get_route(sr.destination)?;
    println!("{:#?}", route);
    Ok(())
}

fn show_routes(_opts: &Opts, _s: &Show, sr: &ShowRoutes) -> Result<()> {
    let mut routes = route::get_routes()?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}",
        "Destination".dimmed(),
        "Gateway".dimmed(),
        "Delay".dimmed(),
        "Interface".dimmed(),
    )?;
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}",
        "-----------".bright_black(),
        "-------".bright_black(),
        "-----".bright_black(),
        "---------".bright_black(),
    )?;

    routes.sort_by_key(|r| r.mask);

    if !sr.v6_only {
        routes
            .iter()
            .filter(|r| r.dest.is_ipv4())
            .filter(|r| !r.dest.is_loopback())
            .for_each(|r| show_route(&mut tw, r).unwrap());
    }
    if !sr.v4_only {
        routes
            .iter()
            .filter(|r| r.dest.is_ipv6())
            .filter(|r| !r.dest.is_loopback())
            .for_each(|r| show_route(&mut tw, r).unwrap());
    }

    tw.flush()?;

    Ok(())
}

fn show_neighbor(_opts: &Opts, _s: &Show, sn: &ShowNeighbor) -> Result<()> {
    let nbr = libnet::get_neighbor(&sn.ifname, sn.addr)?;

    let mut flags = String::new();
    if nbr.is_router() {
        flags += "router";
    }
    if nbr.is_anycast() {
        flags += "anycast";
    }
    if nbr.is_proxy() {
        flags += "proxy";
    }
    if nbr.is_static() {
        flags += "static";
    }

    let m = &nbr.l2_addr;
    println!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x} {}",
        m[0], m[1], m[2], m[3], m[4], m[5], flags,
    );

    Ok(())
}

fn show_route(
    tw: &mut TabWriter<std::io::Stdout>,
    r: &libnet::route::Route,
) -> Result<()> {
    writeln!(
        tw,
        "{}/{}\t{}\t{}\t{}",
        color_ip(r.dest),
        r.mask,
        color_ip(r.gw),
        if r.delay > 0 {
            r.delay.to_string()
        } else {
            "-".dimmed().to_string()
        },
        if let Some(ifx) = &r.ifx {
            ifx.clone()
        } else {
            "-".dimmed().to_string()
        }
    )?;
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

pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(anstyle::Style::new().bold().underline().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .literal(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .invalid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .valid(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(72, 213, 151)),
        )))
        .usage(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(245, 207, 101)),
        )))
        .error(anstyle::Style::new().bold().fg_color(Some(
            anstyle::Color::Rgb(anstyle::RgbColor(232, 104, 134)),
        )))
}
