use super::*;
use anyhow::{Ok, Result};
use std::sync::Arc;
use wintun::{
    self,
    adapter::{WintunAdapter, WintunStream},
};
pub struct VTun(WintunStream);
impl VTun {
    pub async fn read<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let n = self.0.async_read_packet(buf).await?;
        Ok(&buf[..n])
    }

    pub async fn write(&self, buff: &[u8]) -> Result<()> {
        Ok(self.0.write_packet(buff)?)
    }
}

pub(crate) fn create(name: &str, ip: IpInfo) -> Result<VTun> {
    let adapter = Arc::new(WintunAdapter::create_adapter(name, "vpn", "{D4C24D32-A723-DB80-A493-4E32E7883F15}")?);
    adapter.set_ipaddr(ip.ip.as_str(), 24).unwrap();
    let session = adapter.start_session(0x20000).unwrap();
    // 开启tun会话
    Ok(VTun(session))
}
