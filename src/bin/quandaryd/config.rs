// Copyright 2022 Matthew Ingwersen.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may
// obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Implements the server configuration file.

use std::collections::HashSet;
use std::fmt::{self, Write};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use log::Level::Debug;
use log::{debug, log_enabled};
use paste::paste;
use serde::{de, Deserialize};

use quandary::class::Class;
use quandary::db::zone::GluePolicy;
use quandary::message::tsig::Algorithm;
use quandary::name::Name;
use quandary::thread::{self, ThreadGroup};

use crate::args::RunArgs;
use crate::run::Server;

////////////////////////////////////////////////////////////////////////
// CONFIGURATION LOADING                                              //
////////////////////////////////////////////////////////////////////////

/// Loads the server configuration from the file given by `path`.
///
/// The `reloading` parameter controls how the configuration is
/// summarized in the log: if reloading, only the zone and key
/// configurations (the only things that we support reloading) are
/// summarized. This parameter does *not* otherwise affect processing.
pub fn load_from_path(path: impl AsRef<Path>, reloading: bool) -> Result<Config> {
    let dir = match path.as_ref().parent() {
        Some(p) => p,
        None => return Err(anyhow!("the configuration file path has no parent")),
    };
    let raw_config = fs::read(path.as_ref()).context("failed to read the configuration file")?;
    let mut config: Config =
        toml::from_slice(&raw_config).context("failed to parse the configuration file")?;

    // Fail if a zone is configured more than once.
    if let Some((name, class)) = find_duplicated_zone(&config.zones) {
        bail!("the zone {name}/{class} is configured more than once");
    }

    // Fail if a TSIG key is configured more than once.
    if let Some(name) = find_duplicated_tsig_key(&config.tsig_keys) {
        bail!("the TSIG key {name} is configured more than once");
    }

    // When loading the configuration from a path, all zone file paths
    // are interpreted relative to the configuration file's directory.
    for zone_config in &mut config.zones {
        if zone_config.path.is_relative() {
            zone_config.path = dir.join(&zone_config.path);
        }
    }

    if reloading {
        log_zone_and_key_summary(&config);
    } else {
        log_config_summary(&config);
    }
    Ok(config)
}

/// Loads the server configuration from the parsed command line
/// arguments given by `args`.
pub fn load_from_args(args: RunArgs) -> Result<Config> {
    let bind = BindConfig::from(args.bind.unwrap_or_else(|| {
        let ip = args.ip.unwrap_or(DEFAULT_BIND_IP);
        let port = args.port.unwrap_or(DEFAULT_BIND_PORT);
        SocketAddr::new(ip, port)
    }));
    let zones: Vec<_> = args
        .zones
        .into_iter()
        .map(|zd| ZoneConfig {
            name: ConfigName(zd.name),
            class: default_zone_class(),
            glue_policy: default_glue_policy(),
            path: zd.path,
        })
        .collect();

    // Fail if a zone is configured more than once.
    if let Some((name, class)) = find_duplicated_zone(&zones) {
        bail!("the zone {name}/{class} is configured more than once");
    }

    let config = Config {
        bind,
        io: default_io_provider_config(),
        server: None,
        tsig_keys: Vec::new(),
        zones,
    };
    log_config_summary(&config);
    Ok(config)
}

/// Tries to find a duplicated zone (i.e., a name/class combination that
/// is configured more than once) in the configuration.
fn find_duplicated_zone(zones: &[ZoneConfig]) -> Option<(&Name, Class)> {
    let mut zone_set = HashSet::new();
    for zone in zones {
        let pair = (zone.name.0.as_ref(), zone.class.0);
        if !zone_set.insert(pair) {
            return Some(pair);
        }
    }
    None
}

/// Tries to find a duplicated TSIG key in the configuration.
fn find_duplicated_tsig_key(tsig_keys: &[TsigKeyConfig]) -> Option<&Name> {
    let mut key_name_set = HashSet::new();
    for key in tsig_keys {
        let key_name = key.name.0.as_ref();
        if !key_name_set.insert(key_name) {
            return Some(key_name);
        }
    }
    None
}

/// Summarizes the configuration in the log, if the debug log level is
/// enabled.
fn log_config_summary(config: &Config) {
    if !log_enabled!(Debug) {
        // Don't compute the message if it will never be printed.
        return;
    }

    let rrl_status = if config
        .server
        .as_ref()
        .and_then(|s| s.rrl.as_ref())
        .is_some()
    {
        "enabled"
    } else {
        "disabled"
    };

    let mut message = format!(
        "Configuration loaded:\n\
         TCP bind addresses: {}\n\
         UDP bind addresses: {}\n\
         I/O provider:       {}\n\
         RRL:                {}\n\
         Zones:              ",
        config.bind.for_tcp(),
        config.bind.for_udp(),
        config.io.name(),
        rrl_status,
    );
    summarize_zones(&config.zones, &mut message);
    message.write_str("\nTSIG keys:    ").unwrap();
    summarize_keys(&config.tsig_keys, &mut message);
    debug!("{message}");
}

/// Summarizes only the zones and TSIG keys in the log, if the debug log
/// level is enabled. Used when reloading.
fn log_zone_and_key_summary(config: &Config) {
    if log_enabled!(Debug) {
        let mut message = String::from("Zones and keys reloaded:\nZones: ");
        summarize_zones(&config.zones, &mut message);
        message.push_str("\nTSIG keys: ");
        summarize_keys(&config.tsig_keys, &mut message);
        debug!("message");
    }
}

/// Produces the zone summary for [`log_config_summary`] and
/// [`log_zone_and_key_summary`].
fn summarize_zones(zones: &[ZoneConfig], message: &mut String) {
    if zones.is_empty() {
        message.push_str("none to load");
    } else {
        write!(message, "{} to load", zones.len()).unwrap();
        for zone_config in zones {
            write!(
                message,
                "\n  {}/{}",
                zone_config.name.0, zone_config.class.0,
            )
            .unwrap();
        }
    }
}

/// Produces the TSIG key summary for [`log_config_summary`] and
/// [`log_zone_and_key_summary`].
fn summarize_keys(tsig_keys: &[TsigKeyConfig], message: &mut String) {
    if tsig_keys.is_empty() {
        message.push_str("none");
    } else {
        write!(message, "{} configured", tsig_keys.len()).unwrap();
        for key in tsig_keys {
            write!(message, "\n  {} ({})", key.name.0, key.algorithm).unwrap();
        }
    }
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION FILE STRUCTURE                                       //
////////////////////////////////////////////////////////////////////////

/// The complete configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub bind: BindConfig,
    #[serde(default = "default_io_provider_config")]
    pub io: IoProviderConfig,
    pub server: Option<ServerConfig>,
    #[serde(default)]
    pub tsig_keys: Vec<TsigKeyConfig>,
    pub zones: Vec<ZoneConfig>,
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION SECTION: BIND ADDRESSES                              //
////////////////////////////////////////////////////////////////////////

/// Configures the addresses to which the server will bind.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum BindConfig {
    Uniform(BindSpecs),
    PerProtocol { tcp: BindSpecs, udp: BindSpecs },
}

/// One or more [`BindSpec`]s. This type exists so that Serde can parse
/// either a single string or an array of strings where one or more
/// [`BindSpec`]s are needed.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum BindSpecs {
    Single(BindSpec),
    Multiple(Vec<BindSpec>),
}

/// A single datum that specifies one or more addresses to which to
/// bind.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum BindSpec {
    /// A [`SocketAddr`] provided by default or parsed from the command
    /// line. Serde does not parse this variant.
    #[serde(skip)]
    Addr(SocketAddr),

    /// A [`String`] read from a configuration file that is converted
    /// into addresses using [`String`]'s [`ToSocketAddrs`]
    /// implementation. Serde always parses this variant.
    String(String),
}

impl BindConfig {
    /// Returns the [`BindSpecs`] for TCP.
    fn for_tcp(&self) -> &BindSpecs {
        match self {
            Self::Uniform(specs) => specs,
            Self::PerProtocol { tcp, .. } => tcp,
        }
    }

    /// Returns the [`BindSpecs`] for UDP.
    fn for_udp(&self) -> &BindSpecs {
        match self {
            Self::Uniform(specs) => specs,
            Self::PerProtocol { udp, .. } => udp,
        }
    }
}

const DEFAULT_BIND_IP: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const DEFAULT_BIND_PORT: u16 = 53;

impl Default for BindConfig {
    fn default() -> Self {
        Self::from(SocketAddr::new(DEFAULT_BIND_IP, DEFAULT_BIND_PORT))
    }
}

impl From<SocketAddr> for BindConfig {
    fn from(addr: SocketAddr) -> Self {
        Self::Uniform(BindSpecs::Single(BindSpec::Addr(addr)))
    }
}

impl BindSpecs {
    /// Resolves all contained [`BindSpec`]s and collects the results.
    /// See [`BindSpec::resolve`].
    pub fn resolve(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Self::Single(spec) => spec.resolve(),
            Self::Multiple(specs) => {
                let mut addrs = Vec::new();
                for spec in specs {
                    addrs.extend(spec.resolve()?);
                }
                Ok(addrs)
            }
        }
    }
}

impl fmt::Display for BindSpecs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Single(spec) => spec.fmt(f),
            Self::Multiple(specs) => {
                if specs.is_empty() {
                    f.write_str("(none)")
                } else {
                    for spec in specs.iter().take(specs.len() - 1) {
                        spec.fmt(f)?;
                        f.write_str(", ")?;
                    }
                    specs.last().unwrap().fmt(f)
                }
            }
        }
    }
}

impl BindSpec {
    /// Returns the addresses specified by the `BindSpec`, resolving
    /// them if necessary.
    fn resolve(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Self::Addr(a) => Ok(vec![*a]),
            Self::String(s) => s
                .to_socket_addrs()
                .map(Iterator::collect)
                .with_context(|| format!("failed to resolve {s}")),
        }
    }
}

impl fmt::Display for BindSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Addr(a) => a.fmt(f),
            Self::String(s) => s.fmt(f),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION SECTION: I/O PROVIDERS                               //
////////////////////////////////////////////////////////////////////////

/// An abstraction over all supported I/O providers.
pub trait IoProvider {
    fn supports_graceful_shutdown(&self) -> bool;
    fn start(
        self: Box<Self>,
        server: &Arc<Server>,
        group: &Arc<ThreadGroup>,
    ) -> Result<(), thread::Error>;
}

/// The selection of I/O provider and its configuration.
///
/// To actually create the selected provider with its configuration and
/// bind it to an address, use [`IoProviderConfig::bind_provider`].
#[derive(Debug, Deserialize)]
#[serde(tag = "provider")]
pub enum IoProviderConfig {
    #[serde(rename = "blocking")]
    Blocking(blocking_io::Config),
    #[cfg(feature = "tokio")]
    #[serde(rename = "tokio")]
    Tokio,
}

impl IoProviderConfig {
    /// Returns the name of the selected I/O provider.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Blocking(_) => "blocking",
            #[cfg(feature = "tokio")]
            Self::Tokio => "tokio",
        }
    }

    /// Creates the selected I/O provider with this configuration and
    /// binds it to the provided addresses.
    pub fn bind_provider<T, U>(&self, tcp_addrs: T, udp_addrs: U) -> io::Result<Box<dyn IoProvider>>
    where
        T: IntoIterator<Item = SocketAddr>,
        U: IntoIterator<Item = SocketAddr>,
    {
        match self {
            Self::Blocking(config) => {
                let io_provider =
                    quandary::io::BlockingIoProvider::bind(config.into(), tcp_addrs, udp_addrs)?;
                Ok(Box::new(io_provider))
            }
            #[cfg(feature = "tokio")]
            Self::Tokio => {
                let io_provider = tokio_io::TokioIoProviderShim::bind(tcp_addrs, udp_addrs)?;
                Ok(Box::new(io_provider))
            }
        }
    }
}

/// Support for the
/// [`BlockingIoProvider`](quandary::io::BlockingIoProvider).
mod blocking_io {
    use super::*;
    use quandary::io::{BlockingIoConfig, BlockingIoProvider};

    impl IoProvider for BlockingIoProvider {
        fn supports_graceful_shutdown(&self) -> bool {
            BlockingIoProvider::SUPPORTS_GRACEFUL_SHUTDOWN
        }

        fn start(
            self: Box<Self>,
            server: &Arc<Server>,
            group: &Arc<ThreadGroup>,
        ) -> Result<(), thread::Error> {
            BlockingIoProvider::start(*self, server, group)
        }
    }

    /// Provider configuration for the [`BlockingIoProvider`]. This
    /// mirrors [`BlockingIoConfig`] and can be converted into one; its
    /// purpose is basically to make the configuration deserializable
    /// and to provide defaults.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        #[serde(default = "default_tcp_base_workers")]
        tcp_base_workers: usize,
        #[serde(default = "default_tcp_worker_linger")]
        tcp_worker_linger: u64,
        #[serde(default = "default_udp_workers_per_socket")]
        udp_workers_per_socket: usize,
    }

    fn default_tcp_base_workers() -> usize {
        4
    }

    fn default_tcp_worker_linger() -> u64 {
        15
    }

    fn default_udp_workers_per_socket() -> usize {
        2
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                tcp_base_workers: default_tcp_base_workers(),
                tcp_worker_linger: default_tcp_worker_linger(),
                udp_workers_per_socket: default_udp_workers_per_socket(),
            }
        }
    }

    impl From<&Config> for BlockingIoConfig {
        fn from(toml_config: &Config) -> Self {
            Self {
                tcp_base_workers: toml_config.tcp_base_workers,
                tcp_worker_linger: Duration::from_secs(toml_config.tcp_worker_linger),
                udp_workers_per_socket: toml_config.udp_workers_per_socket,
            }
        }
    }
}

/// Support for the [`TokioIoProvider`](quandary::io::TokioIoProvider).
#[cfg(feature = "tokio")]
mod tokio_io {
    use std::io;

    use quandary::io::TokioIoProvider;
    use tokio::runtime::Runtime;

    use super::*;

    /// A shim allowing the synchronous, thread-based core of the daemon
    /// to run the [`TokioIoProvider`].
    pub(super) struct TokioIoProviderShim {
        inner: TokioIoProvider,
        runtime: Runtime,
    }

    impl TokioIoProviderShim {
        /// Binds a [`TokioIoProvider`] and then wraps it up with its
        /// [`Runtime`] in a [`TokioIoProviderShim`].
        pub(super) fn bind<T, U>(tcp_addrs: T, udp_addrs: U) -> io::Result<Self>
        where
            T: IntoIterator<Item = SocketAddr>,
            U: IntoIterator<Item = SocketAddr>,
        {
            let runtime = Runtime::new()?;
            let inner = runtime.block_on(TokioIoProvider::bind(tcp_addrs, udp_addrs))?;
            Ok(Self { inner, runtime })
        }
    }

    impl IoProvider for TokioIoProviderShim {
        fn supports_graceful_shutdown(&self) -> bool {
            true
        }

        fn start(
            self: Box<Self>,
            server: &Arc<Server>,
            group: &Arc<ThreadGroup>,
        ) -> Result<(), thread::Error> {
            // The "shim thread" that we create here integrates the
            // TokioIoProvider with the daemon's core ThreadGroup.
            let server = server.clone();
            let group_clone = group.clone();
            group.start_oneshot(Some(String::from("tokio shim")), move || {
                let _guard = self.runtime.enter();
                let shutdown_handle = TokioIoProvider::start(self.inner, &server);
                group_clone.await_start_of_shutdown();
                shutdown_handle.blocking_shut_down();
            })
        }
    }
}

fn default_io_provider_config() -> IoProviderConfig {
    IoProviderConfig::Blocking(blocking_io::Config::default())
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION SECTION: SERVER                                      //
////////////////////////////////////////////////////////////////////////

/// The configuration for server behavior/options.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub edns_udp_payload_size: Option<u16>,
    pub rrl: Option<RrlConfig>,
}

/// The configuration for response rate-limiting (RRL).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RrlConfig {
    pub noerror_rate: u32,
    pub nxdomain_rate: u32,
    pub error_rate: u32,
    pub window: u32,
    pub slip: Option<usize>,
    pub ipv4_prefix_len: Option<u8>,
    pub ipv6_prefix_len: Option<u8>,
    pub size: Option<usize>,
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION SECTION: TSIG KEYS                                   //
////////////////////////////////////////////////////////////////////////

/// The configuration for a single TSIG key.
#[derive(Clone, Debug, Deserialize)]
pub struct TsigKeyConfig {
    pub name: ConfigName,
    pub algorithm: ConfigAlgorithm,
    #[serde(deserialize_with = "deserialize_secret")]
    pub secret: Box<[u8]>,
}

/// A deserializable wrapper over the
/// [`quandary::message::tsig::Algorithm`] type.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ConfigAlgorithm {
    #[serde(rename = "hmac-sha1")]
    HmacSha1,
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl From<ConfigAlgorithm> for Algorithm {
    fn from(config_algorithm: ConfigAlgorithm) -> Self {
        match config_algorithm {
            ConfigAlgorithm::HmacSha1 => Self::HmacSha1,
            ConfigAlgorithm::HmacSha256 => Self::HmacSha256,
        }
    }
}

impl fmt::Display for ConfigAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HmacSha1 => f.write_str("hmac-sha1"),
            Self::HmacSha256 => f.write_str("hmac-sha256"),
        }
    }
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let raw = <&str>::deserialize(deserializer)?;
    BASE64_STANDARD
        .decode(raw)
        .map(Vec::into_boxed_slice)
        .map_err(|_| de::Error::custom("invalid base-64 encoding"))
}

////////////////////////////////////////////////////////////////////////
// CONFIGURATION SECTION: ZONES                                       //
////////////////////////////////////////////////////////////////////////

/// The configuration of a single zone.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub name: ConfigName,
    #[serde(default = "default_zone_class")]
    pub class: ConfigClass,
    #[serde(default = "default_glue_policy")]
    pub glue_policy: ConfigGluePolicy,
    pub path: PathBuf,
}

fn default_zone_class() -> ConfigClass {
    ConfigClass(Class::IN)
}

/// A deserializable wrapper over the [`quandary::db::zone::GluePolicy`]
/// type.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ConfigGluePolicy {
    #[serde(rename = "narrow")]
    Narrow,
    #[serde(rename = "wide")]
    Wide,
}

fn default_glue_policy() -> ConfigGluePolicy {
    ConfigGluePolicy::Narrow
}

impl From<ConfigGluePolicy> for GluePolicy {
    fn from(config_policy: ConfigGluePolicy) -> Self {
        match config_policy {
            ConfigGluePolicy::Narrow => Self::Narrow,
            ConfigGluePolicy::Wide => Self::Wide,
        }
    }
}

////////////////////////////////////////////////////////////////////////
// WRAPPERS OVER QUANDARY TYPES FOR SERDE                             //
////////////////////////////////////////////////////////////////////////

/// Generates a deserializable `ConfigX` structure wrapping an `X` type
/// from [`quandary`], using its [`FromStr`](std::str::FromStr)
/// implementation.
macro_rules! make_serde_wrapper {
    ($wrapper:ident, $over:ty, $description:literal) => {
        /// A macro-generated deserializable wrapper over a [`quandary`]
        /// type.
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $wrapper(pub $over);

        impl<'de> Deserialize<'de> for $wrapper {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                deserializer.deserialize_str(paste! { [<$wrapper Visitor>] })
            }
        }

        paste! {
            /// A macro-generated [`Visitor`](de::Visitor).
            #[derive(Debug)]
            struct [<$wrapper Visitor>];
        }

        impl<'de> de::Visitor<'de> for paste! { [<$wrapper Visitor>] } {
            type Value = $wrapper;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str($description)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value
                    .parse()
                    .map($wrapper)
                    .map_err(|e| E::custom(format!("invalid {}: {}", $description, e)))
            }
        }
    };
}

make_serde_wrapper!(ConfigName, Box<Name>, "domain name");
make_serde_wrapper!(ConfigClass, Class, "DNS class");
