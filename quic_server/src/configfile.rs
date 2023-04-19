use anyhow::{Context, Result};
use clap::*;
use rcgen::*;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use vpn::*;

#[derive(clap::Parser, Debug)]
#[command(name = "quic_server", about = crate_description!(), version = crate_version!(), author = crate_authors!(), help_template = "\
{before-help}{name} {version}
{author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) action: Action,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Action {
    #[command(about = "create server config")]
    Server {
        #[arg(
            short = 'l',
            long = "listen",
            help = "listen ip and port, i.e. [::1]:4433 or 192.168.10.100:4433"
        )]
        listen: SocketAddr,
        #[arg(long = "ip", help = "server virtual ip to use: i.e. 10.8.67.1")]
        myip: Ipv4Addr,
        #[arg(
            long = "cn",
            help = "Your company's name, this goes into the certificate"
        )]
        companyname: String,
        #[arg(
            long = "domain",
            help = "the domain name, this goes into the certificate"
        )]
        domain: String,
        #[arg(
            long = "dhcpupperbound",
            default_value = "100",
            help = "dhcp range is: 2..=dhcpupperbound. which means when client request a ip, \nit will be assigned with its original ip or pick one from 2 to dhcpupperbound. \nIf client's ip was higher than is, then it's considered static ip."
        )]
        dhcpupperbound: u8,
        #[arg(
            long = "filename",
            default_value = "server.toml",
            help = "the file name to save the server config, default to server.toml"
        )]
        filename: String,
        #[arg(
            long = "tunname",
            default_value = "quic",
            help = "the tun name, default to quic, use different name if you run multiple vpn client/server on the same machine"
        )]
        tunname: String,
    },
    #[command(about = "create client config")]
    Client {
        #[arg(
            short = 'c',
            long = "connect",
            help = "server ip and port to connect to, i.e. 47.36.25.182:4433"
        )]
        connect: SocketAddr,
        #[arg(long = "ip", help = "client local virtual ip to use: i.e. 10.8.67.15")]
        myip: Ipv4Addr,
        #[arg(
            long = "name",
            help = "this client's name, this goes into the certificate"
        )]
        username: String,
        #[arg(
            long = "email",
            help = "this client's email, this goes into the certificate"
        )]
        email: String,
        #[arg(
            long = "host",
            help = "server's domain name, this goes into the certificate"
        )]
        host: String,
        #[arg(
            long = "filename",
            default_value = "client.toml",
            help = "the file name to save the server config, default to client.toml"
        )]
        filename: String,
        #[arg(
            long = "tunname",
            default_value = "quic",
            help = "the tun name, default to quic, use different name if you run multiple vpn client/server on the same machine"
        )]
        tunname: String,
    },
    #[command(about = "create proxy client config")]
    Proxy {
        #[arg(
            short = 'c',
            long = "connect",
            help = "server ip and port to connect to, i.e. 47.36.25.182:4433"
        )]
        connect: SocketAddr,
        #[arg(
            long = "ip",
            default_value = "0.0.0.0:8080",
            help = "local ip:port to listen to as proxy"
        )]
        proxy: SocketAddr,
        #[arg(
            long = "name",
            help = "this client's name, this goes into the certificate"
        )]
        username: String,
        #[arg(
            long = "email",
            help = "this client's email, this goes into the certificate"
        )]
        email: String,
        #[arg(
            long = "host",
            help = "server's domain name, this goes into the certificate"
        )]
        host: String,
        #[arg(
            long = "filename",
            default_value = "client.toml",
            help = "the file name to save the server config, default to client.toml"
        )]
        filename: String,
    },
}

pub(crate) fn processargs() -> Result<()> {
    let args = Args::parse();
    match args.action {
        Action::Server {
            listen,
            myip,
            companyname,
            domain,
            dhcpupperbound,
            filename,
            tunname,
        } => create_server_config(domain, companyname, myip, listen, dhcpupperbound, filename, tunname),
        Action::Client {
            connect,
            myip,
            username,
            email,
            host,
            filename,
            tunname
        } => create_quic_config(username, host, email, connect, filename, "client", |client| VpnClient {
            myip,
            client,
            tunname,
            cmd: Vec::new(),
        }),
        Action::Proxy {
            connect,
            proxy,
            username,
            email,
            host,
            filename,
        } => create_quic_config(username, host, email, connect, filename, "proxy", |client| ProxyClient { proxy, client }),
    }
}

pub(crate) fn get_server_config() -> Result<VpnServer> {
    Ok(loadtoml::<VpnServer>(get_path_as_executable("server.toml")?)
        .context("invalid config file: server.toml. \nPlease ask your admin to generate a config file, name it server.toml, and place it under the same dir as this application.\nrun with --help for more information")?)
} 

pub(crate) fn create_quic_config<T: serde::ser::Serialize>(
    username: String,
    host: String,
    email: String,
    connect: SocketAddr,
    filename: String,
    configtype: &str,
    f: impl FnOnce(QuicClient) -> T,
) -> std::result::Result<(), anyhow::Error> {
    let server = get_server_config()?;
    let key_pair = KeyPair::from_pem(&server.cakey).context("invalid CA key")?;
    let param = CertificateParams::from_ca_cert_pem(&server.cacrt, key_pair)?;
    let ca = Certificate::from_params(param)?;
    let mut param = CertificateParams::default();
    param.distinguished_name.push(rcgen::DnType::CommonName, &username);
    param.distinguished_name.push(rcgen::DnType::OrganizationName, &host);
    param.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, configtype);
    param.subject_alt_names.push(SanType::Rfc822Name(email));
    let cert = Certificate::from_params(param)?;
    let config = f(QuicClient {
        host,
        username,
        connect,
        cacrt: server.cacrt,
        cert: cert.serialize_pem_with_signer(&ca)?,
        key: cert.get_key_pair().serialize_pem(),
    });
    savetoml(&config, filename.into()).context("save client.toml error")
}

pub(crate) fn create_server_config(
    domain: String,
    companyname: String,
    myip: Ipv4Addr,
    listen: SocketAddr,
    dhcpupperbound: u8,
    filename: String,
    tunname: String,
) -> std::result::Result<(), anyhow::Error> {
    let ca = generate_simple_self_signed([domain.clone()])?;
    let mut param = CertificateParams::default();
    param.distinguished_name.push(rcgen::DnType::CommonName, &companyname);
    param.distinguished_name.push(rcgen::DnType::OrganizationName, &domain);
    param.subject_alt_names.push(SanType::DnsName(domain.clone()));
    let cert = Certificate::from_params(param)?;
    let config = VpnServer {
        myip,
        domain,
        companyname,
        listen,
        cakey: ca.get_key_pair().serialize_pem(),
        cacrt: ca.serialize_pem()?,
        key: cert.get_key_pair().serialize_pem(),
        cert: cert.serialize_pem_with_signer(&ca)?,
        cmd: Vec::new(),
        dhcpupperbound,
        tunname
    };
    savetoml(&config, filename.into()).context("save server.toml error")
}
