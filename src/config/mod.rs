pub mod secret;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use http::Method;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    ConfigError, Result,
    metrics::Stats,
    net::{
        dns::Dns,
        egress::{Egress, EgressSpec},
        resolve::{Overrides, ResolveSpec},
        tls::{self, DownstreamTls},
    },
    pool::{ByokPools, Origin, Pool, PoolFactory},
};
use secret::{Fingerprint, Secret};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Openai,
    Claude,
    Gemini,
}

impl Provider {
    pub const ALL: [Self; 3] = [Self::Openai, Self::Claude, Self::Gemini];
    pub fn index(self) -> usize {
        self as usize
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
        }
    }
    pub fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::Claude => "api.anthropic.com",
            Self::Gemini => "generativelanguage.googleapis.com",
        }
    }
    pub fn dns_name(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com.",
            Self::Claude => "api.anthropic.com.",
            Self::Gemini => "generativelanguage.googleapis.com.",
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Byok,
    Managed,
    Disabled,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    pub bind: SocketAddr,
    pub management: SocketAddr,
    pub h3: bool,
    pub quic_retry: bool,
    pub max_connections: usize,
    pub max_in_flight: usize,
    pub max_header_bytes: u32,
    pub streams_per_connection: u32,
    pub header_timeout_secs: u64,
    pub idle_connection_timeout_secs: u64,
}
impl Default for Listen {
    fn default() -> Self {
        Self {
            bind: ([127, 0, 0, 1], 8080).into(),
            management: ([127, 0, 0, 1], 9080).into(),
            h3: false,
            quic_retry: true,
            max_connections: 256,
            max_in_flight: 256,
            max_header_bytes: 32 * 1024,
            streams_per_connection: 64,
            header_timeout_secs: 10,
            idle_connection_timeout_secs: 90,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub connect_timeout_secs: u64,
    pub response_header_timeout_secs: u64,
    pub stream_idle_timeout_secs: u64,
    pub shutdown_drain_timeout_secs: u64,
    pub h3_probe_timeout_ms: u64,
    pub h3_cooldown_secs: u64,
    pub upstream_0rtt: bool,
    pub allow_0rtt_non_idempotent: bool,
    pub byok_pool_capacity: usize,
    pub byok_pool_idle_secs: u64,
    pub websocket: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 5,
            response_header_timeout_secs: 180,
            stream_idle_timeout_secs: 60,
            shutdown_drain_timeout_secs: 30,
            h3_probe_timeout_ms: 750,
            h3_cooldown_secs: 60,
            upstream_0rtt: true,
            allow_0rtt_non_idempotent: false,
            byok_pool_capacity: 32,
            byok_pool_idle_secs: 90,
            websocket: cfg!(feature = "websocket"),
        }
    }
}

fn early_yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSpec {
    pub cert: PathBuf,
    pub key: PathBuf,
    #[serde(default = "early_yes")]
    pub tcp_early_data: bool,
    #[serde(default = "early_yes")]
    pub quic_early_data: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RouteSpec {
    mode: Option<Mode>,
    host: Option<String>,
    byok_egress: Option<String>,
    prefer_h3: bool,
    resolve: Option<ResolveSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedSpec {
    provider: Provider,
    egress: String,
    key: Option<Secret>,
    key_env: Option<String>,
    prefer_h3: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserSpec {
    key: Option<Secret>,
    key_env: Option<String>,
    grants: BTreeMap<Provider, GrantSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantSpec {
    upstream: String,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    #[serde(default)]
    listen: Listen,
    tls: Option<TlsSpec>,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    mode: Mode,
    byok_egress: Option<String>,
    #[serde(default)]
    dns_servers: Vec<SocketAddr>,
    #[serde(default)]
    routes: BTreeMap<Provider, RouteSpec>,
    egress: BTreeMap<String, EgressSpec>,
    #[serde(default)]
    upstreams: BTreeMap<String, ManagedSpec>,
    #[serde(default)]
    users: BTreeMap<String, UserSpec>,
}

pub struct Route {
    pub mode: Mode,
    pub host: Option<String>,
    pub byok_egress: Option<Arc<Egress>>,
    pub prefer_h3: bool,
}

pub(crate) struct Managed {
    pub key: Secret,
    pub pool: Arc<Pool>,
}

pub(crate) struct Grant {
    pub upstream: Arc<Managed>,
    methods: Vec<Method>,
    prefixes: Vec<String>,
}

impl Grant {
    pub fn permits(&self, method: &Method, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.iter().any(|m| m == method))
            && (self.prefixes.is_empty()
                || (scopable_path(path)
                    && self.prefixes.iter().any(|prefix| {
                        path.strip_prefix(prefix).is_some_and(|suffix| {
                            suffix.is_empty() || prefix.ends_with('/') || suffix.starts_with('/')
                        })
                    })))
    }
}

fn scopable_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['%', '\\', ';', '?', '#'])
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_graphic())
        && !path.split('/').any(|s| s == "." || s == "..")
}

struct User {
    fingerprint: Fingerprint,
    grants: [Option<Grant>; 3],
}

pub struct Snapshot {
    pub listen: Listen,
    pub limits: Limits,
    pub tls: Option<DownstreamTls>,
    pub routes: [Route; 3],
    pub(crate) byok: ByokPools,
    pub(crate) factory: PoolFactory,
    users: Vec<User>,
    managed: Vec<Arc<Managed>>,
    pub metrics: BTreeMap<(Provider, Arc<str>), Arc<Stats>>,
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn host_name(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl Snapshot {
    pub fn from_file(path: &Path, previous: Option<&Self>) -> Result<Self> {
        const MAX_CONFIG: u64 = 1024 * 1024;
        let file = File::open(path).map_err(|_| "cannot open configuration file")?;
        let mut input = Zeroizing::new(String::new());
        file.take(MAX_CONFIG + 1)
            .read_to_string(&mut input)
            .map_err(|_| "cannot read UTF-8 configuration")?;
        if input.len() as u64 > MAX_CONFIG {
            return Err("configuration file exceeds 1 MiB".into());
        }
        let disk: Disk = toml::from_str(&input).map_err(|e: toml::de::Error| {
            let line = e
                .span()
                .and_then(|span| input.as_bytes().get(..span.start))
                .map_or(1, |s| 1 + s.iter().filter(|&&b| b == b'\n').count());
            ConfigError(format!(
                "invalid TOML or configuration value at line {line} (content redacted)"
            ))
        })?;
        drop(input);
        let (crypto, roots) = (
            tls::provider(),
            Arc::new(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            )),
        );
        Self::build(
            disk,
            path.parent().unwrap_or(Path::new(".")),
            previous,
            crypto,
            roots,
            Provider::ALL.map(Origin::official),
        )
    }

    fn build(
        mut disk: Disk,
        base: &Path,
        previous: Option<&Self>,
        crypto: Arc<rustls::crypto::CryptoProvider>,
        roots: Arc<rustls::RootCertStore>,
        mut origins: [Origin; 3],
    ) -> Result<Self> {
        validate(&disk)?;
        if let Some(old) = previous
            && (old.listen != disk.listen || old.tls.is_some() != disk.tls.is_some())
        {
            return Err("changing [listen] or enabling/disabling TLS requires restart".into());
        }
        let tls = disk
            .tls
            .as_ref()
            .map(|t| {
                tls::downstream(
                    t,
                    base,
                    crypto.clone(),
                    disk.listen.h3,
                    disk.listen.streams_per_connection,
                    disk.listen.max_connections,
                )
            })
            .transpose()?;
        let resolver = Arc::new(Dns::new(&disk.dns_servers)?);
        let mut egresses = HashMap::new();
        let mut metrics = BTreeMap::new();
        let validate_udp = disk.routes.values().any(|r| r.prefer_h3)
            || disk.upstreams.values().any(|u| u.prefer_h3 == Some(true));
        for (name, spec) in disk.egress {
            let egress = Arc::new(Egress::new(&name, spec, resolver.clone(), validate_udp)?);
            for provider in Provider::ALL {
                let label = (provider, egress.name.clone());
                let stats = previous
                    .and_then(|old| old.metrics.get(&label))
                    .cloned()
                    .unwrap_or_default();
                metrics.insert(label, stats);
            }
            egresses.insert(name, egress);
        }
        let mut hosts = HashSet::new();
        let mut routes = Vec::with_capacity(3);
        for provider in Provider::ALL {
            let spec = disk.routes.remove(&provider).unwrap_or_default();
            if let Some(host) = &spec.host
                && (!host_name(host) || !hosts.insert(host.to_ascii_lowercase()))
            {
                return Err("invalid or duplicate provider host route".into());
            }
            let mode = spec.mode.unwrap_or(disk.mode);
            let byok_egress = spec
                .byok_egress
                .as_ref()
                .or(disk.byok_egress.as_ref())
                .map(|name| {
                    egresses
                        .get(name)
                        .cloned()
                        .ok_or("unknown BYOK egress reference")
                })
                .transpose()?;
            if mode == Mode::Byok && byok_egress.is_none() {
                return Err("each BYOK route needs a default or per-route egress".into());
            }
            if let Some(resolve) = spec.resolve {
                let slot = provider.index();
                let old = previous.and_then(|s| s.factory.origins[slot].resolve.as_deref());
                let overrides = Overrides::build(
                    resolve,
                    base,
                    old,
                    resolver.clone(),
                    crypto.clone(),
                    roots.clone(),
                )
                .map_err(|e| ConfigError(format!("routes.{}.resolve: {e}", provider.name())))?;
                origins[slot].resolve = Some(Arc::new(overrides));
            }
            routes.push(Route {
                mode,
                host: spec.host,
                byok_egress,
                prefer_h3: spec.prefer_h3,
            });
        }
        let routes: [Route; 3] = routes.try_into().map_err(|_| "invalid route count")?;
        let factory = PoolFactory {
            crypto,
            roots,
            origins,
            limits: disk.limits.clone(),
            max_header_bytes: disk.listen.max_header_bytes,
        };
        let mut domains = HashMap::<_, Arc<Managed>>::new();
        let mut official_keys = HashSet::new();
        let mut upstreams = HashMap::new();
        for (name, spec) in disk.upstreams {
            let provider = spec.provider;
            let egress = egresses
                .get(&spec.egress)
                .cloned()
                .ok_or("unknown managed upstream egress")?;
            if !egress.fixed() {
                return Err(
                    "Managed upstreams require fixed source addresses, not wildcard egress".into(),
                );
            }
            let key = secret::load(spec.key, spec.key_env.as_deref())?;
            let fingerprint = Fingerprint::new(key.checked()?);
            official_keys.insert(fingerprint);
            let want_h3 = spec.prefer_h3.unwrap_or(routes[provider.index()].prefer_h3);
            let id = (provider, egress.name.clone(), fingerprint, want_h3);
            let entry = if let Some(entry) = domains.get(&id) {
                entry.clone()
            } else {
                let stats = metrics
                    .get(&(provider, egress.name.clone()))
                    .cloned()
                    .ok_or("inconsistent egress metrics")?;
                let pool = factory.build(provider, egress, stats, want_h3)?;
                let entry = Arc::new(Managed { key, pool });
                domains.insert(id, entry.clone());
                entry
            };
            upstreams.insert(name, (provider, entry));
        }
        let mut fingerprints = HashSet::new();
        let mut users = Vec::with_capacity(disk.users.len());
        for (_, spec) in disk.users {
            let secret = secret::load(spec.key, spec.key_env.as_deref())?;
            let key = secret.checked()?;
            if key.len() < 24 {
                return Err(
                    "managed UserKey must be at least 24 characters; use high-entropy tokens"
                        .into(),
                );
            }
            let fingerprint = Fingerprint::new(key);
            if official_keys.contains(&fingerprint) {
                return Err("a UserKey cannot also be an official key".into());
            }
            if !fingerprints.insert(fingerprint) {
                return Err("duplicate managed UserKey".into());
            }
            let mut grants = [None, None, None];
            if spec.grants.is_empty() {
                return Err("UserKey has no provider grants".into());
            }
            for (provider, grant) in spec.grants {
                let (actual, upstream) = upstreams
                    .get(&grant.upstream)
                    .ok_or("unknown upstream in UserKey grant")?;
                if *actual != provider || routes[provider.index()].mode != Mode::Managed {
                    return Err("UserKey grant provider/mode mismatch".into());
                }
                let methods = grant
                    .methods
                    .iter()
                    .map(|method| {
                        Method::from_bytes(method.as_bytes()).map_err(|_| "invalid grant method")
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                if grant.path_prefixes.len() > 32
                    || methods.len() > 16
                    || grant
                        .path_prefixes
                        .iter()
                        .any(|p| !scopable_path(p) || p.len() > 512)
                {
                    return Err("invalid managed grant scope".into());
                }
                grants[provider.index()] = Some(Grant {
                    upstream: upstream.clone(),
                    methods,
                    prefixes: grant.path_prefixes,
                });
            }
            users.push(User {
                fingerprint,
                grants,
            });
        }
        let byok = ByokPools::new(
            disk.limits.byok_pool_capacity,
            disk.limits.byok_pool_idle_secs,
        );
        Ok(Self {
            listen: disk.listen,
            tls,
            routes,
            limits: disk.limits,
            byok,
            factory,
            users,
            managed: domains.into_values().collect(),
            metrics,
        })
    }

    pub fn schedule_endpoint_refresh(
        &self,
        tasks: &tokio_util::task::TaskTracker,
        stop: &tokio_util::sync::CancellationToken,
    ) {
        for provider in Provider::ALL {
            let slot = provider.index();
            if self.routes[slot].mode != Mode::Disabled
                && let Some(resolve) = &self.factory.origins[slot].resolve
            {
                resolve.schedule(provider.name(), tasks, stop);
            }
        }
    }

    pub async fn maintain(&self) {
        for entry in &self.managed {
            entry.pool.reap_idle();
        }
        self.byok.reap().await;
    }
    pub(crate) fn is_user_key(&self, candidate: &[u8]) -> bool {
        self.user(candidate).is_some()
    }
    pub(crate) fn authenticate(&self, candidate: &[u8], provider: Provider) -> Option<&Grant> {
        self.user(candidate)?.grants[provider.index()].as_ref()
    }
    fn user(&self, candidate: &[u8]) -> Option<&User> {
        if self.users.is_empty() {
            return None;
        }
        let candidate = Fingerprint::new(candidate);
        let mut chosen = self.users.len();
        // No early return. All slots get the same 32-byte compare and mask operation.
        for (i, user) in self.users.iter().enumerate() {
            let mask = 0usize.wrapping_sub(candidate.ct_eq(user.fingerprint).unwrap_u8() as usize);
            chosen = (chosen & !mask) | (i & mask);
        }
        self.users.get(chosen)
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        text: &str,
        base: &Path,
        origins: [Origin; 3],
        roots: Arc<rustls::RootCertStore>,
    ) -> Result<Self> {
        let disk = toml::from_str(text).map_err(|_| "invalid test TOML")?;
        Self::build(disk, base, None, tls::provider(), roots, origins)
    }
}

fn validate(d: &Disk) -> Result<()> {
    let l = &d.listen;
    let t = &d.limits;
    if l.h3 && d.tls.is_none() {
        return Err("HTTP/3 downstream requires [tls]".into());
    }
    if !l.management.ip().is_loopback() {
        return Err("management bind must be loopback".into());
    }
    if l.management == l.bind && l.bind.port() != 0 {
        return Err("management must have a separate socket".into());
    }
    if !(1..=16_384).contains(&l.max_connections)
        || !(1..=16_384).contains(&l.max_in_flight)
        || !(1..=512).contains(&l.streams_per_connection)
        || !(8192..=131_072).contains(&l.max_header_bytes)
        || !(1..=120).contains(&l.header_timeout_secs)
        || !(1..=3600).contains(&l.idle_connection_timeout_secs)
    {
        return Err("listener resource limit out of range".into());
    }
    if !(1..=60).contains(&t.connect_timeout_secs)
        || !(1..=3600).contains(&t.response_header_timeout_secs)
        || !(1..=3600).contains(&t.stream_idle_timeout_secs)
        || !(1..=600).contains(&t.shutdown_drain_timeout_secs)
        || !(50..=5000).contains(&t.h3_probe_timeout_ms)
        || !(1..=3600).contains(&t.h3_cooldown_secs)
        || !(1..=1024).contains(&t.byok_pool_capacity)
        || !(5..=3600).contains(&t.byok_pool_idle_secs)
    {
        return Err("invalid timeouts or pool capacity".into());
    }
    if t.websocket && !cfg!(feature = "websocket") {
        return Err("websocket config requires Cargo feature websocket".into());
    }
    if d.dns_servers.len() > 8
        || d.dns_servers
            .iter()
            .any(|a| a.ip().is_unspecified() || a.port() == 0)
    {
        return Err("invalid DNS server list".into());
    }
    if d.egress.is_empty()
        || d.egress.len() > 64
        || d.upstreams.len() > 128
        || d.users.len() > 1024
        || d.egress
            .keys()
            .chain(d.upstreams.keys())
            .chain(d.users.keys())
            .any(|n| !identifier(n))
    {
        return Err("invalid name or too many egresses/upstreams/users".into());
    }
    Ok(())
}
