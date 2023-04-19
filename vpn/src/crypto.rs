use super::*;
use anyhow::{Context, Result};
use quinn::{ClientConfig, Connection};
use rtls::{self, client, sign, SignatureScheme};
use serde::*;
use std::sync::Arc;
use x509_parser::prelude::*;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[derive(Serialize, Deserialize)]
pub struct VpnClient {
    pub client: QuicClient,
    pub myip: std::net::Ipv4Addr,
    pub cmd: Vec<String>,
    pub tunname: String
}

#[derive(Serialize, Deserialize)]
pub struct ProxyClient {
    pub client: QuicClient,
    pub proxy: std::net::SocketAddr,
}

#[derive(Serialize, Deserialize)]
pub struct QuicClient {
    pub cacrt: String,
    pub key: String,
    pub cert: String,
    pub username: String,
    pub host: String,
    pub connect: std::net::SocketAddr,
}

#[derive(Serialize, Deserialize)]
pub struct VpnServer {
    pub cakey: String,
    pub cacrt: String,
    pub key: String,
    pub cert: String,
    pub companyname: String,
    pub domain: String,
    pub listen: std::net::SocketAddr,
    pub myip: std::net::Ipv4Addr,
    pub cmd: Vec<String>,
    pub dhcpupperbound: u8,
    pub tunname: String
}

macro_rules! getcrypt {
    ($a:ident) => {
        impl $a {
            pub fn get_cryptoinfo(&self) -> Result<(Vec<rtls::Certificate>, rtls::PrivateKey, rtls::RootCertStore)> {
                Ok((get_pemcert(&self.cert)?, get_pemkey(&self.key)?, get_pemroots(get_pemcert(&self.cacrt)?)?))
            }
        }
    };
}

macro_rules! fallback {
    ($a:expr) => { $a };
    ($a:expr, $($b:expr),*) => {if let Some(x) = $a { x } else { fallback!($($b),*) } };
}


getcrypt!(QuicClient);
getcrypt!(VpnServer);

impl VpnClient {
    pub fn get_cryptoinfo(&self) -> Result<(Vec<rtls::Certificate>, rtls::PrivateKey, rtls::RootCertStore)> {
        self.client.get_cryptoinfo()
    }
}

impl ProxyClient {
    pub fn get_cryptoinfo(&self) -> Result<(Vec<rtls::Certificate>, rtls::PrivateKey, rtls::RootCertStore)> {
        self.client.get_cryptoinfo()
    }
}

pub fn get_pemcert(data: &str) -> Result<Vec<rtls::Certificate>> {
    let mut data = data.as_bytes();
    Ok(rustls_pemfile::certs(&mut data).context("invalid PEM-encoded certificate")?.into_iter().map(rtls::Certificate).collect())
}

pub fn get_pemkey(data: &str) -> Result<rtls::PrivateKey> {
    let mut data = data.as_bytes();
    Ok(rtls::PrivateKey(fallback!(
        rustls_pemfile::pkcs8_private_keys(&mut data)? //assume pem file won't fail for pkcs8 or rsa
            .into_iter()
            .next(),
        rustls_pemfile::rsa_private_keys(&mut data)?.into_iter().next().context("no private keys found")?
    )))
}

pub fn get_pemroots(certs: Vec<rtls::Certificate>) -> Result<rtls::RootCertStore> {
    let mut roots = rtls::RootCertStore::empty();
    certs.iter().map(|x| roots.add(x)).count();
    Ok(roots)
}

pub fn showcert<'a>(c: &'a X509Certificate<'a>) -> &'a X509Certificate<'a> {
    showcertname("issuer", &c.issuer);
    showcertname("Subject", &c.subject);
    if let Ok(Some(names)) = c.subject_alternative_name() {
        for name in names.value.general_names.iter() {
            println!("{}", name);
        }
    }
    println!("version: {:#?}, serial: {}, signature: {:#?}", c.version, c.serial, c.signature);
    c
}

fn showcertname(title: &str, name: &X509Name) {
    println!(
        "{}: common name: {} country: {}, state: {}, locality: {}, organization: {}, orgnizationalunit: {}, email: {}",
        title,
        name.iter_common_name().name(),
        name.iter_country().name(),
        name.iter_state_or_province().name(),
        name.iter_locality().name(),
        name.iter_organization().name(),
        name.iter_organizational_unit().name(),
        name.iter_email().name()
    );
}

pub trait IMutName<'a> {
    fn name(&mut self) -> &'a str;
}

impl<'a, T> IMutName<'a> for T
where T : Iterator<Item = &'a AttributeTypeAndValue<'a>> {
    fn name(&mut self) -> &'a str {
        self.next().map_or("",|c| c.as_str().unwrap_or(""))
    }
}


pub async fn connect(cfg: &QuicClient) -> Result<Connection> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

    endpoint.set_default_client_config(configure_client(cfg)?);

    info!("connecting to {} at {}", cfg.host, cfg.connect);
    endpoint.connect(cfg.connect, &cfg.host)?.await.context("failed to connect")
}

fn configure_client(cfg: &QuicClient) -> Result<ClientConfig> {
    let (cert, key, roots) = cfg.get_cryptoinfo()?;
    info!("added {} roots", roots.len());
    let resolver = CertResolver(Arc::new(sign::CertifiedKey::new(cert, sign::any_supported_type(&key).context("invalid private key")?)));
    let mut client_crypto = rtls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        //.with_no_client_auth();
        .with_client_cert_resolver(Arc::new(resolver));
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut c = ClientConfig::new(Arc::new(client_crypto));
    c.transport_config(Arc::new(create_transport_config()));
    Ok(c)
}

struct CertResolver(Arc<sign::CertifiedKey>);
impl client::ResolvesClientCert for CertResolver {
    fn resolve(&self, _acceptable_issuers: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
