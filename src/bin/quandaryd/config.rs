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

use std::fmt::{self, Write};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::Level::Debug;
use log::{debug, log_enabled};
use paste::paste;
use serde::{de, Deserialize};

use quandary::class::Class;
use quandary::db::zone::GluePolicy;
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
/// summarized in the log: if reloading, only the zone configuration
/// (the only thing that we support reloading) is summarized. This
/// parameter does *not* otherwise affect processing.
pub fn load_from_path(path: impl AsRef<Path>, reloading: bool) -> Result<Config> {
    let dir = match path.as_ref().parent() {
        Some(p) => p,
        None => return Err(anyhow!("the configuration file path has no parent")),
    };
    let raw_config = fs::read(path.as_ref()).context("failed to read the configuration file")?;
    let mut config: Config =
        toml::from_slice(&raw_config).context("failed to parse the configuration file")?;

    // When loading the configuration from a path, all zone file paths
    // are interpreted relative to the configuration file's directory.
    for zone_config in &mut config.zones {
        if zone_config.path.is_relative() {
            zone_config.path = dir.join(&zone_config.path);
        }
    }

    if reloading {
        log_zone_summary(&config.zones);
    } else {
        log_config_summary(&config);
    }
    Ok(config)
}

/// Loads the server configuration from the parsed command line
/// arguments given by `args`.
pub fn load_from_args(args: RunArgs) -> Config {
    let bind = args.bind.unwrap_or_else(|| {
        let ip = args.ip.unwrap_or(DEFAULT_BIND_IP);
        let port = args.port.unwrap_or(DEFAULT_BIND_PORT);
        SocketAddr::new(ip, port)
    });

    let config = Config {
        bind,
        io: default_io_provider_config(),
        server: None,
        zones: args
            .zones
            .into_iter()
            .map(|zd| ZoneConfig {
                name: ConfigName(zd.name),
                class: default_zone_class(),
                glue_policy: default_glue_policy(),
                path: zd.path,
            })
            .collect(),
    };
    log_config_summary(&config);
    config
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
         Bind address: {}\n\
         I/O provider: {}\n\
         RRL:          {}\n\
         Zones:        ",
        config.bind,
        config.io.name(),
        rrl_status,
    );
    summarize_zones(&config.zones, &mut message);
    debug!("{}", message);
}

/// Summarizes only the zones in the log, if the debug log level is
/// enabled. Used when reloading.
fn log_zone_summary(zones: &[ZoneConfig]) {
    if log_enabled!(Debug) {
        let mut message = String::from("Catalog reloaded:\nZones: ");
        summarize_zones(zones, &mut message);
        debug!("{}", message);
    }
}

/// Produces the zone summary for [`log_config_summary`] and
/// [`log_zone_summary`].
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

////////////////////////////////////////////////////////////////////////
// CONFIGURATION FILE STRUCTURE                                       //
////////////////////////////////////////////////////////////////////////

/// The complete configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_io_provider_config")]
    pub io: IoProviderConfig,
    pub server: Option<ServerConfig>,
    pub zones: Vec<ZoneConfig>,
}

const DEFAULT_BIND_IP: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const DEFAULT_BIND_PORT: u16 = 53;

fn default_bind() -> SocketAddr {
    SocketAddr::new(DEFAULT_BIND_IP, DEFAULT_BIND_PORT)
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
}

impl IoProviderConfig {
    /// Returns the name of the selected I/O provider.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Blocking(_) => "blocking",
        }
    }

    /// Creates the selected I/O provider with this configuration and
    /// binds it to the provided address.
    pub fn bind_provider(&self, addr: SocketAddr) -> io::Result<Box<dyn IoProvider>> {
        match self {
            Self::Blocking(config) => {
                let io_provider = quandary::io::BlockingIoProvider::bind(config.into(), addr)?;
                Ok(Box::new(io_provider))
            }
        }
    }
}

/// Support for the
/// [`BlockingIoProvider](quandary::io::BlockingIoProvider).
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
        #[serde(default = "default_listeners")]
        tcp_listeners: usize,
        #[serde(default = "default_tcp_base_workers")]
        tcp_base_workers: usize,
        #[serde(default = "default_tcp_worker_linger")]
        tcp_worker_linger: u64,
        #[serde(default = "default_udp_workers")]
        udp_workers: usize,
    }

    fn default_listeners() -> usize {
        1
    }

    fn default_tcp_base_workers() -> usize {
        4
    }

    fn default_tcp_worker_linger() -> u64 {
        15
    }

    fn default_udp_workers() -> usize {
        2
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                tcp_listeners: default_listeners(),
                tcp_base_workers: default_tcp_base_workers(),
                tcp_worker_linger: default_tcp_worker_linger(),
                udp_workers: default_udp_workers(),
            }
        }
    }

    impl From<&Config> for BlockingIoConfig {
        fn from(toml_config: &Config) -> Self {
            Self {
                tcp_listeners: toml_config.tcp_listeners,
                tcp_base_workers: toml_config.tcp_base_workers,
                tcp_worker_linger: Duration::from_secs(toml_config.tcp_worker_linger),
                udp_workers: toml_config.udp_workers,
            }
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
        #[derive(Clone, Debug)]
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
