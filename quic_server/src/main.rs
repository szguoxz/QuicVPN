use anyhow::{bail, Context, Result};
use bytes::*;
use log::*;
use rustls::server::AllowAnyAuthenticatedClient;
use std::{collections::HashMap, env, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::sync::*;
use vpn::vpntun::*;
use vpn::*;
use x509_parser::prelude::*;
use scopeguard::guard;
mod configfile;

/*
steps:
    1. check arguments, create configuration files if there're any args
    2. load configuration file
    3. create virtual NIC: tun
    4. create quic listener
    5. start listen, and dispatch tun packets to all connected connection, communicated through a channel for adding/removing connection
    --------------------
    listener:
    1. if it's proxy, process proxy request, or else, it's a vpn connection.
 */
#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    if env::args().count() > 1 {
        return configfile::processargs();
    }

    let cfg = configfile::get_server_config()?;
    let ip = cfg.myip;
    let tun = create_tun(&cfg.tunname, ip)?;

    println!("tun created, start listening on quic");
    println!("you may need to run iptables to to enable ip forward and SNAT");
    println!("You can also add the following to server.toml file");
    println!("sample cmds:");
    let cmd = r#"cmd = ["iptables -t nat -C POSTROUTING -s {} ! -d {} -j SNAT --to-source localip || iptables -t nat -A POSTROUTING -s {} ! -d {} -j SNAT --to-source localip",
    "iptables -C FORWARD -s {} -j ACCEPT || iptables -A FORWARD -s {} -j ACCEPT"]"#;
    println!("{}", cmd);
    println!("replace localip with your local ip address, most likely the same ip you listen on");

    let ip0 = ip.octets();
    let ip0 = format!("{}.{}.{}.0/24", ip0[0], ip0[1], ip0[2]);
    for cmd in &cfg.cmd {
        run_cmd(cmd.to_string().replace("{}", &ip0));
    }
    QuicServer {
        tun,
        clients: std::sync::Mutex::new(HashMap::new()),
        cfg,
    }
    .listen()
    .await
}

struct QuicServer {
    tun: VTun,
    clients: std::sync::Mutex<HashMap<[u8; 4], mpsc::Sender<Bytes>>>,
    cfg: VpnServer,
}

impl QuicServer {
    async fn listen(self) -> Result<()> {
        let listener = self.create_listener().await?;
        let this = Arc::new(self);
        this.clone().dispatchtunmsg().show_error("dispatch tun  msg").start();

        info!("listening: {:#?}", listener.local_addr());
        loop {
            let Some(conn) = listener.accept().await else {
                println!("accept error");
                sleepforsecs(60).await;
                continue;
            };
            let Ok(conn) = conn.show_error("connecting error").await else {
                sleepforsecs(60).await;
                continue;
            };
            info!("accepted");
            match Self::showpeer(&conn) {
                Ok(p) if p == "proxy" => Self::processproxy(conn).show_error("process proxy").start(),
                _ => this.clone().connectiontotun(conn).show_error("conn to tun").start(),
            }
        }
    }


    async fn connectiontotun(self: Arc<Self>, conn: quinn::Connection) -> Result<()> {
        info!("new connection came in");
        let (mut quicsender, mut quicreceiver) = conn.accept_bi().await?;

        //read conn IP address
        let mut ip = [0u8; 4];
        quicreceiver.read_exact(&mut ip).await?;
        info!("read ip in {:?}", ip);

        let (msgqueue, mut tunmsg) = mpsc::channel::<Bytes>(5000);

        info!("new client with ip {:?}", ip);

        {
            let mut cl = self.clients.lock().unwrap();
            if self.cfg.dhcpupperbound > 0 && ip[3] < self.cfg.dhcpupperbound{
                //verify ip:
                if cl.contains_key(&ip) || ip[3] < 2 {
                    ip[3] = 2;
                    while cl.contains_key(&ip) {
                        if ip[3] < self.cfg.dhcpupperbound {
                            ip[3] += 1;
                        } else {
                            ip[3] = 0; //do not have enough IP. 0 to inform the client
                            break; //we only use ip  2..=dhcpcount
                        }
                    }
                }
            }
            info!("confirmed client with ip {:?}", ip);
            //send ip back to connection to confirm ip
            cl.insert(ip, msgqueue);
        }
        
        let this = guard(self, |this|{ this.clients.lock().unwrap().remove_entry(&ip); info!("ip {:?} removed", ip) });

        //send confirmed ip back
        quicsender.writeflush(&ip).await?;

        if ip[3] == 0 {
            bail!("do not have enough IP, close this connection now");
        }
        //start forwarding bi-direction
        tokio::select!(
            //by pass the kernel if the destination is other clients.
            r = connection_to_tun(quicreceiver, &this.tun, |p|!this.forward_client_packet(p)) => r,
            r = async move {
                while let Some(msg) = tunmsg.recv().await {
                    write_packet(&mut quicsender,msg.as_ref()).await?;
                }
                anyhow_ok(())
            } => r
        )
    }

    fn forward_client_packet(&self, p: &[u8]) -> bool {
        let Some(ip) = filter_header(p) else {
            info!("tun read not valid packet");
            return true; //processed
        };
        let ip = ip.destination();
        //we may want to do a IP mapping here, so it will be more flexible

        let mut cl = self.clients.lock().unwrap();
        if let Some(queue) = cl.get_mut(&ip) {
            if queue.try_send(Bytes::copy_from_slice(p)).is_err() {
                cl.remove_entry(&ip);
            }
            return true;
        }
        false
    }
    
    async fn dispatchtunmsg(self: Arc<Self>) -> Result<()> {
        let mut d = tokio::io::sink();
        tun_to_connection(&self.tun, &mut d, |p| !self.forward_client_packet(p)).await
    }


    async fn create_listener(&self) -> Result<quinn::Endpoint> {
        let (cert_chain, key, roots) = self.cfg.get_cryptoinfo()?;
        info!("added {} roots", roots.len());

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(roots))
            .with_single_cert(cert_chain, key)?;
        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

        // if options.keylog {
        //     server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        // }

        let mut c = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        c.transport_config(Arc::new(create_transport_config()));
        Ok(quinn::Endpoint::server(c, self.cfg.listen)?)
    }

    fn showpeer(conn: &quinn::Connection) -> Result<String> {
        for c in conn.peer_identity().context("no id")?.downcast::<Vec<rustls::Certificate>>().ok().context("not a certificate")?.iter() {
            match X509Certificate::from_der(c.as_ref()) {
                Ok((_, c)) => return Ok(showcert(&c).subject().iter_organizational_unit().name().to_string()),
                _ => println!("not valid certificate: {:?}", c.as_ref()),
            }
        }
        Ok("".into())
    }

    async fn processproxy(conn: quinn::Connection) -> Result<()> {
        info!("processing proxy request");
        loop {
            let (mut sender, mut receiver) = conn.accept_bi().await?;
            let mut buf = [0u8; 2048];

            async move {
                let host = read_conn_packet(&mut receiver, &mut buf).timeoutsecs(2).await??.to_utf8()?;
                sender.write_u16(12345).timeoutsecs(1).await??;
                info!("connect to {}", host);
                pipe(tokio::net::TcpStream::connect(host).await?, sender, receiver).start();
                anyhow_ok(())
            }
            .show_error("request error")
            .start();
        }
    }
}
