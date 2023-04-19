use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use log::*;
use notify::{RecursiveMode, Watcher};
use once_cell::sync::Lazy;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::{Arc, Mutex},
};
use tokio::{io::AsyncReadExt, net::*};
use tokio_util::sync::CancellationToken;
use vpn::*;

macro_rules! continuetosleep {
    ($a: ident = $n:expr, $($b:expr),*) => { println!($($b),*); $a = $n; continue; }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let cfg = loadtoml::<ProxyClient>(get_path_as_executable("client.toml")?).context("can't load configuration file: client.toml. Please ask your admin to generate a config file, name it client.toml, and place it under the same dir as this application")?;
    println!("start proxy");
    let mut sleepseconds = 0;
    'restart: loop {
        if sleepseconds > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(sleepseconds)).await;
        } else {
            sleepseconds = 0;
        }
        let Ok(conn) = vpn::crypto::connect(&cfg.client).await else {
            continuetosleep!(sleepseconds = 60, "connection failed, will try again in 1 minute");
        };
        let conn = Arc::new(conn);
        println!("connected to quic server {}", cfg.client.connect);
        let Ok(listener) = TcpListener::bind(cfg.proxy).await else {
            continuetosleep!(sleepseconds = 60, "proxy binding {:#?} failed, will try again in 1 minute", cfg.proxy);
        };
        println!("proxy listening on {}", cfg.proxy);
        let token = CancellationToken::new();
        loop {
            let Some(accepted) = listener.accept().cancelby(token.clone()).await else {
                println!("connection got cancelled, will try again now");
                continue 'restart;
            };
            let Ok((socket, _)) = accepted else {
                println!("proxy listen accept failed, will try again in 1 minute");
                sleepseconds = 60;
                continue 'restart;
            };
            ProxyServer {
                conn: conn.clone(),
                socket,
            }
            .start_forward(token.clone())
            .show_error("forward error")
            .start();
        }
    }
}

struct ProxyServer {
    conn: Arc<quinn::Connection>,
    socket: TcpStream,
}

impl ProxyServer {
    async fn start_forward(mut self, token: CancellationToken) -> Result<()> {
        let mut buf = BytesMut::with_capacity(4096);
        let host = self.read_host(&mut buf).await?;
        if PROXY_MATCHER.lock().unwrap().should_use_proxy(host.as_str()) {
            let (mut sender, receiver) = self.open_tunnel(&host).await.map_err(|e| {
                token.cancel();
                e
            })?;
            sender.writeflush(buf.as_ref()).await?;
            pipe(self.socket, sender, receiver).await;
        } else {
            //connect host directly
            let mut server = tokio::net::TcpStream::connect(host).await?;
            server.writeflush(buf.as_ref()).await?;
            tokio::io::copy_bidirectional(&mut self.socket, &mut server).await.ok();
        }
        Ok(())
    }

    async fn read_host(&mut self, buf: &mut BytesMut) -> Result<String> {
        Ok(loop {
            if self.socket.read_buf(buf).await? == 0 {
                bail!("partial request");
            }
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers);
            if let httparse::Status::Complete(n) = req.parse(buf.as_ref())? {
                if req.method.context("invalid method")? == "CONNECT" {
                    let host = req.path.context("path error")?.to_string();
                    self.socket.writeflush(b"HTTP/1.0 200 Connection Established\r\n\r\n").await?;
                    if buf.len() == n {
                        buf.clear();
                    } else {
                        buf.copy_within(n.., 0);
                        let remaining = buf.len() - n;
                        info!("{} bytes left, shouod never happen", remaining);
                        buf.truncate(remaining);
                    }
                    break if host.contains(':') {
                        host
                    } else {
                        format!("{host}:443")
                    };
                } else {
                    let findheader = |name| Some(req.headers.iter().find(|x| x.name.to_lowercase() == name)?.value.to_utf8());
                    let host = findheader("host").context("no host found")?.context("invalid host")?;
                    break if host.contains(':') {
                        host.to_string()
                    } else if let Some(port) = findheader("port") {
                        format!("{}:{}", host, port?.parse::<u16>()?)
                    } else {
                        format!("{host}:80")
                    };
                }
            }
        })
    }

    async fn open_tunnel(&self, host: &String) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut sender, mut receiver) = self.conn.open_bi().timeoutsecs(1).await??;
        write_packet(&mut sender, host.as_bytes()).timeoutsecs(1).await??;
        receiver.read_u16().timeoutsecs(2).await??;
        Ok((sender, receiver))
    }
}

struct ProxyMatcher {
    patterns: Vec<String>,
    domains: Vec<String>,
    #[allow(dead_code)]
    watcher: notify::RecommendedWatcher,
}
static PROXY_MATCHER: Lazy<Mutex<ProxyMatcher>> = Lazy::new(ProxyMatcher::new);
impl ProxyMatcher {
    fn new() -> Mutex<Self> {
        let mut watcher = notify::recommended_watcher(move |res| {
            if let Ok(_) = res {
                if let Ok((_, p, d)) = ProxyMatcher::load_config() {
                    let mut m = PROXY_MATCHER.lock().unwrap();
                    m.patterns = p;
                    m.domains = d;
                } else {
                    error!("load proxy.conf error");
                }
            }
        })
        .unwrap();
        let (c, p, d) = ProxyMatcher::load_config().unwrap();
        watcher.watch(c.as_path(), RecursiveMode::NonRecursive).ok();
        Mutex::new(ProxyMatcher {
            patterns: p,
            domains: d,
            watcher,
        })
    }
    fn should_use_proxy(&self, host: &str) -> bool {
        let hostlowercase = host.to_lowercase();
        let Some(host) = hostlowercase.split(':').next() else {
            return false;
        };
        for domain in &self.domains {
            if host.ends_with(domain) {
                info!("proxy request {hostlowercase}, ends with {domain}");
                return true;
            }
        }

        for pattern in &self.patterns {
            if host.contains(pattern) {
                info!("proxy request {hostlowercase}, contains {pattern}");
                return true;
            }
        }
        println!("connect directly request {hostlowercase}");
        false
    }

    fn load_config() -> Result<(std::path::PathBuf, Vec<String>, Vec<String>)> {
        let config = get_path_as_executable("proxy.conf")?;
        info!("loading config file {:#?}", config);
        let mut patterns = Vec::new();
        let mut domains = Vec::new();
        for line in BufReader::new(File::open(config.as_path())?).lines().filter_map(|x| x.ok()).map(|x| x.to_lowercase()) {
            if let Some(stripped) = line.strip_prefix('^') {
                patterns.push(stripped.to_string());
            } else {
                domains.push(line);
            }
        }
        info!("read {} domains, {} regex patterns from {:#?}", domains.len(), patterns.len(), config);
        Ok((config, patterns, domains))
    }
}
