//uncomment this to hide console window
//#![windows_subsystem = "windows"]
use anyhow::{Context};
use futures::FutureExt;
use log::*;
use std::net::Ipv4Addr;
use tokio::time::*;
use vpn::*;

/*
   connection steps:
   1. load configuration file
   2. connect to quic server
   3. send my ip, try to keep my own ip
   4. get back confirmed ip, might be changed my server
   5. create virtual NIC: tun, and set its IP
   6. add any route or dns if necessary by executing any command in configuration
   7. start to forward packet back and forth
   sample cmd in client.toml
   cmd = ["route add -net 192.168.10.0 netmask 255.255.255.0 gw {}",
        "iptables -t nat -L vpnsnat -n || iptables -t nat -N vpnsnat",
        "iptables -t nat -C POSTROUTING -s 192.168.90.0/24 -d 192.168.10.0/24 -j vpnsnat || iptables -t nat -A POSTROUTING -s 192.168.90.0/24 -d 192.168.10.0/24 -j vpnsnat",
        "iptables -t nat -F vpnsnat",
        "iptables -t nat -A vpnsnat -s 192.168.90.0/24 -d 192.168.10.0/24 -j SNAT --to-source {}"]
*/
macro_rules! continuetosleep {
    ($a: ident = $n:expr, $($b:expr),*) => { println!($($b),*); $a = $n; continue; }
}

#[tokio::main]
async fn main() {
    init_logger();
    let cfg = loadtoml::<VpnClient>(get_path_as_executable("client.toml").unwrap()).context("can't load configuration file: client.toml. Please ask your admin to generate a config file, name it client.toml, and place it under the same dir as this application").unwrap();
    let mut sleepseconds = 0;
    //allow panic in above code, from now on, handle every error
    println!("start vpn client, connection to: {:#?}", cfg.client.connect);
    let mut ip = cfg.myip;
    loop {
        if sleepseconds > 0 {
            sleepforsecs(sleepseconds).await;
        }
        let core::result::Result::Ok(conn) = vpn::crypto::connect(&cfg.client).await else {
            continuetosleep!(sleepseconds = 60, "connection failed, will try again in 1 minute");
        };
        let core::result::Result::Ok((mut sender, mut receiver)) = conn.open_bi().await else {
            continuetosleep!(sleepseconds = 60, "open stream failed, will try to reconnect in 1 minute");
        };
        println!("connected. sending my ip {}", &ip);
        let mut ipbuf = ip.octets();
        let ff = async {
            sender.writeflush(&ipbuf).await?;
            receiver.read_exact(&mut ipbuf).await?;
            anyhow_ok(())
        };
        if ff.await.is_err() {
            continuetosleep!(sleepseconds = 60, "ip verification error, will try to connect again in a minute");
        }
        if ipbuf[3] == 0 {
            continuetosleep!(sleepseconds = 600, "server does not have enough IP!, will try again in 10 minutes");
        }
        ip = Ipv4Addr::from(ipbuf);
        println!("confirmed ip {}", &ip);
        let Ok(tun) = create_tun(&cfg.tunname, ip) else {
            continuetosleep!(sleepseconds = 60, "create tun failed!, will try again in a minute");
        };

        info!("virtual NIC created. Wait for 5 seconds before executing any extra command, like set the route");
        sleep(Duration::from_secs(5)).await;
        for cmd in &cfg.cmd {
            run_cmd(cmd.to_string().replace("{}", ip.to_string().as_str()));
        }

        info!("start to forward");
        println!("NOTE: you need to set up your own route to use the VPN.");
        info!("");
        tokio::join!(
            connection_to_tun(receiver, &tun, |_|true).show_error("connectiontotun").map(|_| ()),
            tun_to_connection(&tun, &mut sender, |p|filter_header(p).filter(|t|t.source_addr().eq(&ip)).is_some()).show_error("tuntoconnection").map(|_| ())
        );
        info!("restart client, wait for 5 seconds");
        sleepseconds = 5;
    }
}