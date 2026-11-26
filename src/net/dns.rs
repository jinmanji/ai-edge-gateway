use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolveHosts, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::xfer::Protocol,
};

use crate::Result;

pub struct Dns(TokioResolver);

impl Dns {
    pub fn new(servers: &[SocketAddr]) -> Result<Self> {
        let mut builder = if servers.is_empty() {
            TokioResolver::builder_tokio().map_err(
                |_| "system DNS unavailable; set dns_servers explicitly (especially on Termux)",
            )?
        } else {
            let mut cfg = ResolverConfig::new();
            for &addr in servers {
                cfg.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                cfg.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
            }
            TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
        };
        let opts = builder.options_mut();
        opts.cache_size = 128;
        opts.timeout = Duration::from_secs(2);
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
        Ok(Self(builder.build()))
    }

    pub async fn addresses(&self, fqdn: &str, port: u16, v6: bool) -> VecDeque<SocketAddr> {
        // Literal IPs are only used by internal/test Origin constructors.
        if let Ok(ip) = fqdn.parse::<IpAddr>() {
            return if ip.is_ipv6() == v6 {
                [SocketAddr::new(ip, port)].into()
            } else {
                VecDeque::new()
            };
        }
        if v6 {
            self.0
                .ipv6_lookup(fqdn)
                .await
                .map(|records| {
                    records
                        .iter()
                        .take(8)
                        .map(|a| SocketAddr::new(IpAddr::V6(a.0), port))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.0
                .ipv4_lookup(fqdn)
                .await
                .map(|records| {
                    records
                        .iter()
                        .take(8)
                        .map(|a| SocketAddr::new(IpAddr::V4(a.0), port))
                        .collect()
                })
                .unwrap_or_default()
        }
    }
}
