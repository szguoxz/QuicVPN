use super::*;
use anyhow::{bail, Result};
use tokio_tun::*;
pub struct VTun(tokio_tun::Tun);

impl VTun {
    pub async fn read<'a>(&self, buff: &'a mut [u8]) -> Result<&'a [u8]> {
        let n = self.0.recv(buff).await?;
        Ok(&buff[..n])
    }

    pub async fn write(&self, buff: &[u8]) -> Result<()> {
        let _ = self.0.send(buff).await?;
        Ok(())
    }
}

pub(crate) fn create(name: &str, ip: IpInfo) -> Result<VTun> {
    let Ok(tun) = TunBuilder::new()
        .name(name)
        .packet_info(false)
        .try_build() else {
            bail!("create tun error, {}", name);
        };

    println!("tun created {}, {}", name, tun.name());

    //cmd("ip", &["link", "add", "name", name, "type", "dummy"]);
    run_cmd(format!("ip addr add dev {} {}", name, ip.mask.as_str()));
    run_cmd(format!("ip link set up dev {}", name));
    Ok(VTun(tun))
}