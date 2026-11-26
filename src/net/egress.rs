use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::{
    net::TcpStream,
    time::{Instant, sleep_until, timeout},
};

use crate::{ConfigError, Result, net::dns::Dns};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpMode {
    V4Only,
    V6Only,
    DualStack,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyPreference {
    PreferV4,
    PreferV6,
    #[default]
    HappyEyeballs,
}

const fn race_delay() -> u64 {
    250
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressSpec {
    pub mode: IpMode,
    pub local_v4: Option<Ipv4Addr>,
    pub local_v6: Option<Ipv6Addr>,
    #[serde(default)]
    pub strategy: FamilyPreference,
    #[serde(default = "race_delay")]
    pub happy_eyeballs_delay_ms: u64,
    #[serde(default)]
    pub freebind: bool,
    pub interface: Option<String>,
    #[serde(default)]
    pub allow_wildcard: bool,
}

pub struct Egress {
    pub name: Arc<str>,
    spec: EgressSpec,
    dns: Arc<Dns>,
}

impl Egress {
    pub fn new(name: &str, spec: EgressSpec, dns: Arc<Dns>, validate_udp: bool) -> Result<Self> {
        let valid_families = match spec.mode {
            IpMode::V4Only => spec.local_v4.is_some() && spec.local_v6.is_none(),
            IpMode::V6Only => spec.local_v4.is_none() && spec.local_v6.is_some(),
            IpMode::DualStack => spec.local_v4.is_some() && spec.local_v6.is_some(),
        };
        if !valid_families {
            return Err(ConfigError(format!(
                "egress {name}: local_v4/local_v6 must match mode"
            )));
        }
        if !(10..=2_000).contains(&spec.happy_eyeballs_delay_ms) {
            return Err("happy_eyeballs_delay_ms must be in 10..=2000".into());
        }
        if let Some(interface) = &spec.interface
            && (interface.is_empty()
                || interface.len() > 15
                || !interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')))
        {
            return Err("invalid egress interface name".into());
        }
        let this = Self {
            name: name.into(),
            spec,
            dns,
        };
        // Linux can globally permit nonlocal binds. Verify interface membership
        // separately, so an omitted freebind flag does not silently inherit that
        // sysctl. Android apps may be unable to enumerate interfaces via netlink.
        #[cfg(target_os = "linux")]
        let assigned = if !this.spec.freebind
            && [this.local(false), this.local(true)]
                .into_iter()
                .flatten()
                .any(|a| !a.ip().is_unspecified())
        {
            Some(if_addrs::get_if_addrs().map_err(|_| "cannot enumerate local egress interfaces")?)
        } else {
            None
        };
        for local in [this.local(false), this.local(true)].into_iter().flatten() {
            match local.ip() {
                IpAddr::V4(ip) if ip.is_broadcast() || ip.is_multicast() => {
                    return Err("invalid IPv4 bind address".into());
                }
                IpAddr::V6(ip)
                    if ip.is_multicast()
                        || ip.to_ipv4_mapped().is_some()
                        || ip.is_unicast_link_local() =>
                {
                    return Err("invalid IPv6 bind address (multicast, mapped, or link-local without a scope ID)".into());
                }
                ip if ip.is_unspecified() && !this.spec.allow_wildcard => {
                    return Err(
                        "egress IP must be fixed unless allow_wildcard is explicitly set".into(),
                    );
                }
                _ => {}
            }
            #[cfg(target_os = "linux")]
            if let Some(addresses) = assigned.as_ref().filter(|_| !local.ip().is_unspecified()) {
                if !addresses.iter().any(|a| {
                    a.ip() == local.ip()
                        && this
                            .spec
                            .interface
                            .as_deref()
                            .is_none_or(|dev| dev == a.name.as_str())
                }) {
                    return Err(ConfigError(format!(
                        "egress {name}: cannot bind {local} (freebind=false): address is not assigned to the configured local interface(s)"
                    )));
                }
            }
            let validate = (|| -> io::Result<()> {
                this.bind(local, false)?;
                if validate_udp {
                    this.bind(local, true)?;
                }
                Ok(())
            })();
            if let Err(e) = validate {
                return Err(ConfigError(format!(
                    "egress {name}: cannot bind {local} (freebind={}): {e}; verify address, interface and permissions",
                    this.spec.freebind
                )));
            }
        }
        Ok(this)
    }

    pub fn fixed(&self) -> bool {
        [self.local(false), self.local(true)]
            .into_iter()
            .flatten()
            .all(|a| !a.ip().is_unspecified())
    }

    pub(crate) fn local(&self, v6: bool) -> Option<SocketAddr> {
        let ip = if v6 {
            IpAddr::V6(self.spec.local_v6?)
        } else {
            IpAddr::V4(self.spec.local_v4?)
        };
        Some(SocketAddr::new(ip, 0))
    }

    fn bind(&self, local: SocketAddr, udp: bool) -> io::Result<Socket> {
        let socket = Socket::new(
            Domain::for_address(local),
            if udp { Type::DGRAM } else { Type::STREAM },
            Some(if udp { Protocol::UDP } else { Protocol::TCP }),
        )?;
        socket.set_nonblocking(true)?;
        if local.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        if !udp {
            socket.set_reuse_address(true)?;
            socket.set_tcp_nodelay(true)?;
            socket.set_tcp_keepalive(
                &TcpKeepalive::new()
                    .with_time(Duration::from_secs(45))
                    .with_interval(Duration::from_secs(15))
                    .with_retries(3),
            )?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(interface) = &self.spec.interface {
                socket.bind_device(Some(interface.as_bytes()))?;
            }
            if self.spec.freebind {
                if local.is_ipv6() {
                    socket.set_freebind_v6(true)?;
                } else {
                    socket.set_freebind_v4(true)?;
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        if self.spec.freebind || self.spec.interface.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface/freebind is Linux-specific",
            ));
        }
        socket.bind(&local.into())?;
        Ok(socket)
    }

    pub async fn tcp(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        let local = self
            .local(remote.is_ipv6())
            .ok_or_else(|| io::Error::other("address family disabled"))?;
        let socket = self.bind(local, false)?;
        tokio::net::TcpSocket::from_std_stream(socket.into())
            .connect(remote)
            .await
    }

    pub fn endpoints(&self) -> io::Result<[Option<quinn::Endpoint>; 2]> {
        let open = |v6| -> io::Result<Option<quinn::Endpoint>> {
            self.local(v6)
                .map(|local| {
                    let socket = self.bind(local, true)?;
                    quinn::Endpoint::new(
                        quinn::EndpointConfig::default(),
                        None,
                        socket.into(),
                        Arc::new(quinn::TokioRuntime),
                    )
                })
                .transpose()
        };
        Ok([open(false)?, open(true)?])
    }

    /// Race the whole transport establishment, including TLS. Scoped futures
    /// cancel losing dials and don't keep sockets alive after a dropped request.
    pub async fn race<T, F, Fut>(
        &self,
        fqdn: &str,
        port: u16,
        budget: Duration,
        connect: F,
    ) -> io::Result<T>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        timeout(budget, self.race_inner(fqdn, port, connect))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connection deadline"))?
    }

    async fn race_inner<T, F, Fut>(&self, fqdn: &str, port: u16, connect: F) -> io::Result<T>
    where
        F: Fn(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let mut lookup = [self.local(false).is_some(), self.local(true).is_some()];
        let dns_v4 = self.dns.addresses(fqdn, port, false);
        let dns_v6 = self.dns.addresses(fqdn, port, true);
        tokio::pin!(dns_v4, dns_v6);
        let preferred = if matches!(self.spec.strategy, FamilyPreference::PreferV4) {
            0
        } else {
            1
        };
        let delay = Duration::from_millis(self.spec.happy_eyeballs_delay_ms);
        let resolution_delay = if matches!(self.spec.strategy, FamilyPreference::HappyEyeballs) {
            Duration::from_millis(50)
        } else {
            delay
        };
        let mut queues = [VecDeque::new(), VecDeque::new()];
        let mut attempts = FuturesUnordered::new();
        let mut last = None;
        let mut last_error = io::Error::other("no DNS address in permitted families");
        let mut next_dial = Instant::now();
        let mut alternate_at = None;
        loop {
            let now = Instant::now();
            let first = last.map_or(preferred, |family| 1 - family);
            let available = [first, 1 - first]
                .into_iter()
                .find(|&i| !queues[i].is_empty());
            let launch_at = available.map(|family| {
                if last.is_none() && family != preferred && lookup[preferred] {
                    *alternate_at.get_or_insert(now + resolution_delay)
                } else if attempts.is_empty() {
                    now
                } else {
                    next_dial
                }
            });
            if let (Some(i), Some(at)) = (available, launch_at)
                && now >= at
                && let Some(addr) = queues[i].pop_front()
            {
                attempts.push(connect(addr));
                last = Some(i);
                next_dial = now + delay;
                continue;
            }
            if !lookup[0] && !lookup[1] && attempts.is_empty() && launch_at.is_none() {
                return Err(last_error);
            }
            tokio::select! {
                addresses = &mut dns_v4, if lookup[0] => { lookup[0] = false; queues[0] = addresses; }
                addresses = &mut dns_v6, if lookup[1] => { lookup[1] = false; queues[1] = addresses; }
                result = attempts.next(), if !attempts.is_empty() => {
                    match result {
                        Some(Ok(value)) => return Ok(value),
                        Some(Err(e)) => { last_error = e; next_dial = Instant::now(); }
                        None => {}
                    }
                }
                _ = sleep_until(launch_at.unwrap_or(now)), if launch_at.is_some() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::{Message, MessageType},
        rr::{
            RData, Record, RecordType,
            rdata::{A, AAAA},
        },
    };
    use tokio::{
        net::{TcpListener, UdpSocket},
        sync::mpsc,
    };

    fn spec(mode: IpMode) -> EgressSpec {
        EgressSpec {
            mode,
            local_v4: (!matches!(mode, IpMode::V6Only)).then_some(Ipv4Addr::LOCALHOST),
            local_v6: (!matches!(mode, IpMode::V4Only)).then_some(Ipv6Addr::LOCALHOST),
            strategy: FamilyPreference::HappyEyeballs,
            happy_eyeballs_delay_ms: 60,
            freebind: false,
            interface: None,
            allow_wildcard: false,
        }
    }

    #[tokio::test]
    async fn exact_dns_families_and_happy_eyeballs_fallback() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap();
        let (tx, mut received) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut buf = [0; 2048];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                let Ok(input) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let Some(q) = input.queries().first() else {
                    continue;
                };
                let _ = tx.send(q.query_type());
                let mut r = Message::new();
                r.set_id(input.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_available(true)
                    .add_query(q.clone());
                let answer = match q.query_type() {
                    RecordType::A => RData::A(A(Ipv4Addr::LOCALHOST)),
                    RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    _ => continue,
                };
                r.add_answer(Record::from_rdata(q.name().clone(), 30, answer));
                socket.send_to(&r.to_vec().unwrap(), from).await.unwrap();
            }
        });
        let dns = Arc::new(Dns::new(&[port]).unwrap());
        for ipv6 in [false, true] {
            let record = if ipv6 {
                RecordType::AAAA
            } else {
                RecordType::A
            };
            let mode = if ipv6 { IpMode::V6Only } else { IpMode::V4Only };
            let listener_addr = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
            let Ok(listener) = TcpListener::bind(listener_addr).await else {
                assert!(ipv6, "IPv4 loopback is required");
                let results = dns.addresses("local.gateway.test.", 443, true).await;
                assert_eq!(results[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
                assert_eq!(received.recv().await.unwrap(), record);
                server.abort();
                return;
            };
            let tcp_port = listener.local_addr().unwrap().port();
            let profile = Egress::new("test", spec(mode), dns.clone(), true).unwrap();
            let transport = profile
                .race(
                    "local.gateway.test.",
                    tcp_port,
                    Duration::from_secs(2),
                    |addr| profile.tcp(addr),
                )
                .await
                .unwrap();
            assert_eq!(transport.local_addr().unwrap().is_ipv6(), ipv6);
            let (_, src) = listener.accept().await.unwrap();
            assert_eq!(
                src.ip(),
                if ipv6 {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                } else {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                }
            );
            assert_eq!(received.recv().await.unwrap(), record);
            assert!(received.try_recv().is_err());
        }
        let dual = Egress::new("dual", spec(IpMode::DualStack), dns.clone(), true).unwrap();
        let started = Instant::now();
        let v4 = dual
            .race(
                "local.gateway.test.",
                443,
                Duration::from_secs(2),
                |addr| async move {
                    if addr.is_ipv6() {
                        std::future::pending::<io::Result<SocketAddr>>().await
                    } else {
                        Ok(addr)
                    }
                },
            )
            .await
            .unwrap();
        assert!(v4.is_ipv4());
        assert!(started.elapsed() >= Duration::from_millis(55));
        // Both A and AAAA were served by the very same resolver's TTL cache.
        assert!(received.try_recv().is_err());
        server.abort();
    }
}
