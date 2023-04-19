use anyhow::{Context, Result};
use etherparse::{InternetSlice, Ipv4HeaderSlice, SlicedPacket};
use futures::future::*;
use log::info;
use quinn::TransportConfig;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use std::{fmt::Debug, task::Poll};
use tokio::time::{Instant, Timeout};
use tokio::{io::*, join};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
pub mod crypto;
pub use crypto::*;
use pin_project::pin_project;
use std::pin::Pin;

#[cfg(windows)]
#[path = "wintun.rs"]
pub mod vpntun;
#[cfg(unix)]
#[path = "linuxtun.rs"]
pub mod vpntun;

#[inline]
pub fn anyhow_ok<T>(x: T) -> Result<T> {
    Ok(x)
}

pub fn create_transport_config() -> TransportConfig {
    let mut t: TransportConfig = Default::default();
    t.max_idle_timeout(Some(quinn::VarInt::from_u32(60_000).into())).keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    t
}

pub async fn write_packet<T: AsyncWriteExt + Unpin>(sender: &mut T, packet: &[u8]) -> Result<()> {
    sender.write_u16(packet.len().try_into()?).await?;
    sender.write_all(packet).await?;
    sender.flush().await?;
    Ok(())
}

pub async fn read_conn_packet<'a>(receiver: &mut quinn::RecvStream, buf: &'a mut [u8]) -> Result<&'a [u8], anyhow::Error> {
    let n: usize = receiver.read_u16().await.context("conn read length")?.into();
    receiver.read_exact(&mut buf[..n]).await.context("conn read packet bytes")?;
    Ok(&buf[..n])
}

pub async fn connection_to_tun(mut receiver: quinn::RecvStream, tun: &vpntun::VTun, filter: impl Fn(&[u8]) -> bool) -> Result<()> {
    let mut buf = [0u8; 1600];
    loop {
        let p = read_conn_packet(&mut receiver, &mut buf).await?;
        if filter(p) {
            tun.write(p).await?;
        }
    }
}

pub async fn tun_to_connection<T: AsyncWriteExt + Unpin>(tun: &vpntun::VTun, sender: &mut T, filter: impl Fn(&[u8]) -> bool) -> Result<()> {
    let mut buf = [0u8; 1600];
    loop {
        let p = tun.read(&mut buf).await.context("tun read")?;
        if filter(p) {
            write_packet(sender, p).await?;
        }
    }
}

static PIPES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub async fn pipe(mut socket: tokio::net::TcpStream, mut sender: impl AsyncWriteExt + Unpin, mut receiver: impl AsyncReadExt + Unpin) {
    let (mut reader, mut writer) = socket.split();
    let start = Instant::now();
    let total = PIPES.fetch_add(1, std::sync::atomic::Ordering::Release);
    info!("start to pipe, {} pipes waiting", total + 1);

    let _ = join!(
        async move {
            tokio::io::copy(&mut reader, &mut sender).slide_timeoutsecs(5).await;
            sender.shutdown().await
        },
        async move {
            tokio::io::copy(&mut receiver, &mut writer).slide_timeoutsecs(5).await;
            writer.shutdown().await
        }
    );
    let total = PIPES.fetch_sub(1, std::sync::atomic::Ordering::Release);
    info!("piped {} seconds, {} pipes waiting", start.elapsed().as_secs(), total - 1);
}

pub fn create_tun(name: &str, ipv4: std::net::Ipv4Addr) -> Result<vpntun::VTun> {
    let ip = ipv4.to_string();
    vpntun::create(
        name,
        IpInfo {
            ip: ip.clone(),
            mask: ip + "/24",
        },
    )
}

pub fn filter_header(packet: &[u8]) -> Option<Ipv4HeaderSlice> {
    let Ok(SlicedPacket {
        ip: Some(InternetSlice::Ipv4(ip, _)),
        ..
    }) = SlicedPacket::from_ip(packet) else { return None; };

    let des = ip.destination_addr();
    if des.is_broadcast() || des.is_multicast() || des.octets()[3] == 255 {
        return None;
    }
    Some(ip)
}

#[derive(Debug)]
pub struct IpInfo {
    #[allow(dead_code)]
    ip: String,
    #[allow(dead_code)]
    mask: String,
}

pub fn sleepforsecs(secs: u64) -> tokio::time::Sleep {
    tokio::time::sleep(std::time::Duration::from_secs(secs))
}

pub fn init_logger() {
    env_logger::Builder::from_default_env()
        .format(|buf, rec| writeln!(buf, "{} [{}] - {}", chrono::Local::now().format("%Y/%m/%d %T"), rec.level(), rec.args()))
        .init();
}

pub fn savetoml<T: serde::ser::Serialize>(c: &T, p: PathBuf) -> Result<()> {
    let toml = toml::to_string_pretty(c)?;
    std::fs::write(&p, toml.as_bytes())?;
    info!("{} saved", p.display());
    Ok(())
}

pub fn loadtoml<T: serde::de::DeserializeOwned>(p: PathBuf) -> Result<T> {
    Ok(toml::from_str::<T>(String::from_utf8_lossy(std::fs::read(p)?.as_ref()).as_ref())?)
}

pub fn get_path_as_executable(p: &str) -> Result<PathBuf> {
    let mut file_path = std::env::current_exe()?;
    file_path.pop(); // remove executable name
    file_path.push(p);
    Ok(file_path)
}

impl<T: ?Sized> IFutureUtil for T where T: Future {}
pub trait IFutureUtil: Future {
    fn start(self)
    where
        Self: Send + Sized + 'static,
        Self::Output: Send + 'static,
    {
        tokio::spawn(self);
    }
    fn timeoutsecs(self, secs: u64) -> Timeout<Self>
    where
        Self: Sized,
    {
        tokio::time::timeout(Duration::from_secs(secs), self)
    }
    fn slide_timeoutsecs(self, secs: u64) -> SlideTimeout<Self>
    where
        Self: Sized,
    {
        SlideTimeout {
            fut: self,
            slide: sleepforsecs(secs),
            interval: Duration::from_secs(secs),
        }
    }
    fn cancelby(self, token: CancellationToken) -> CancellableFuture<Self>
    where
        Self: Sized,
    {
        CancellableFuture {
            fut: self,
            cancelled: token.cancelled_owned(),
        }
    }
    fn show_error<R, E, T: ToString>(self, msg: T) -> ShowError<Self>
    where
        Self: Sized + Future<Output = Result<R, E>>,
        E: Debug,
    {
        ShowError {
            fut: self,
            msg: msg.to_string(),
        }
    }
}

pub trait SliceUtil {
    fn to_utf8(&self) -> Result<&str, std::str::Utf8Error>;
}

impl SliceUtil for [u8] {
    fn to_utf8(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self)
    }
}

#[pin_project]
pub struct ShowError<T> {
    #[pin]
    fut: T,
    msg: String,
}

impl<T, R, E> Future for ShowError<T>
where
    T: Future<Output = Result<R, E>>,
    E: Debug,
{
    type Output = Result<R, E>;
    fn poll(self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        me.fut.poll(cx).map_err(|e| {
            info!("{}, error: {:#?}", me.msg, e);
            e
        })
    }
}

trait IPollMapPendding<T> {
    fn map_pendding<F>(self, f: F) -> Poll<T>
    where
        F: FnOnce() -> Self;

    fn map_or_else<F, F1, U>(self, f: F, f1: F1) -> Poll<U>
    where
        F: FnOnce(T) -> U,
        F1: FnOnce() -> Poll<U>;
}
impl<T> IPollMapPendding<T> for Poll<T> {
    fn map_pendding<F>(self, f: F) -> Self
    where
        F: FnOnce() -> Self,
    {
        if self.is_ready() {
            self
        } else {
            f()
        }
    }
    fn map_or_else<F, F1, U>(self, f: F, f1: F1) -> Poll<U>
    where
        F: FnOnce(T) -> U,
        F1: FnOnce() -> Poll<U>,
    {
        if let Poll::Ready(v) = self {
            Poll::Ready(f(v))
        } else {
            f1()
        }
    }
}

#[pin_project]
pub struct CancellableFuture<T> {
    #[pin]
    fut: T,
    #[pin]
    cancelled: WaitForCancellationFutureOwned,
}

impl<T> Future for CancellableFuture<T>
where
    T: Future,
{
    type Output = Option<T::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        // First, try polling the future
        me.fut.poll(cx).map_or_else(Some, || me.cancelled.poll(cx).map(|_| None))
    }
}

#[pin_project]
pub struct SlideTimeout<T> {
    #[pin]
    fut: T,
    #[pin]
    slide: tokio::time::Sleep,
    interval: Duration,
}

impl<T> Future for SlideTimeout<T>
where
    T: Future,
{
    type Output = Option<T::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        // First, try polling the future
        me.fut.poll(cx).map_or_else(Some, || {
            if me.slide.is_elapsed() {
                None.into()
            } else {
                me.slide.as_mut().reset(Instant::now() + *me.interval);
                me.slide.poll(cx).map(|_| None)
            }
        })
    }
}

impl<T: AsyncWriteExt + Unpin + Sized> IWriteFlush for T {}
pub trait IWriteFlush {
    fn writeflush<'a>(&'a mut self, b: &'a [u8]) -> WriteFlushFuture<'a, Self>
    where
        Self: AsyncWriteExt + Unpin + Sized,
    {
        WriteFlushFuture::<'a, Self> { w: self, b }
    }
}
pub struct WriteFlushFuture<'a, T> {
    w: &'a mut T,
    b: &'a [u8],
}
impl<'a, T> WriteFlushFuture<'a, T>
where
    T: AsyncWriteExt + Unpin,
{
    async fn writeflush(&mut self) -> Result<()> {
        if self.b.len() > 0 {
            self.w.write_all(self.b).await?;
            self.w.flush().await?;
        }
        Ok(())
    }
}

impl<'a, T> Future for WriteFlushFuture<'a, T>
where
    T: AsyncWriteExt + Unpin,
{
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let f = self.get_mut().writeflush();
        tokio::pin!(f);
        f.poll(cx)
    }
}

#[cfg(windows)]
pub fn run_cmd(cmd: String) {
    println!("{}", cmd);
    // linux and mac will be added later
    std::process::Command::new("cmd").arg("/C").arg(cmd).output().unwrap();
}

#[cfg(unix)]
pub fn run_cmd(cmd: String) {
    println!("running command: {}", cmd);
    let output = std::process::Command::new("sh").arg("-c").arg(cmd).output().expect("Failed to execute command");
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
}
