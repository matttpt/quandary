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

//! Implements the `run` command (i.e., running the server).

use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use env_logger::Env;
use log::{error, info, warn};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use quandary::io::socket::SUPPORTS_LOCAL_ADDRESS_SELECTION;
use quandary::server::{RrlParams, TsigKeyMap};
use quandary::thread::ThreadGroup;

use crate::args::RunArgs;
use crate::config::{self, ConfigName, RrlConfig, ServerConfig, TsigKeyConfig, ZoneConfig};
use crate::zones::{self, Catalog};

/// The specific [`Server`](quandary::server::Server) type we use.
pub type Server = quandary::server::Server<Catalog>;

/// Runs the server.
pub fn run(args: RunArgs) {
    env_logger::init_from_env(Env::new().default_filter_or("warn"));

    if let Err(e) = try_running(args) {
        let mut message = String::from("Failed to run:");
        for (i, cause) in e.chain().enumerate() {
            write!(message, "\n[{}] {}", i + 1, cause).unwrap();
        }
        message.push_str("\nExiting with failure.");
        error!("{}", message);
        process::exit(1);
    }
    info!("Exiting with success.");
}

fn try_running(run_args: RunArgs) -> Result<()> {
    info!(
        "Quandary daemon v{}.{}.{} starting.",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH"),
    );

    // Get the configuration, either from the file system or from the
    // command line arguments, as appropriate.
    let (config, reload_source) = if let Some(ref config_path) = run_args.config {
        info!("Loading the configuration from {}.", config_path.display());
        let config = config::load_from_path(config_path, false)
            .context("failed to load the configuration")?;
        let reload_source = ReloadSource::Config(config_path.as_path());
        (config, reload_source)
    } else {
        info!("Loading the configuration from the command line.");
        let config =
            config::load_from_args(run_args).context("failed to load the configuration")?;
        let reload_source = ReloadSource::Args(config.zones.clone());
        (config, reload_source)
    };

    // Before we bind, warn if we don't have local address selection but
    // need it to guarantee proper behavior.
    if !SUPPORTS_LOCAL_ADDRESS_SELECTION && config.bind.ip().is_unspecified() {
        warn!(
            "The IP address to bind ({}) is an unspecified address. \
             Local address selection is not supported on this target. \
             If the system has more than one IP address, the server \
             may use the wrong source address for UDP packets.",
            config.bind.ip(),
        );
    }

    // Create/bind the I/O provider and set up the server. We want to do
    // these before we load zones: zone loading may be very expensive,
    // so it's better to fail fast.
    let io_provider = config
        .io
        .bind_provider(config.bind)
        .context("failed to bind sockets")?;
    let mut server = Server::new(Arc::new(Catalog::new()));
    if let Some(ref server_config) = config.server {
        configure_server(&mut server, server_config)?;
    }

    // Load the zones.
    if config.zones.len() == 1 {
        info!("Beginning to load 1 zone.");
    } else {
        info!("Beginning to load {} zones.", config.zones.len());
    }
    let mut catalog = Arc::new(zones::load(config.zones));
    server.set_catalog(catalog.clone());

    // Load any configured TSIG keys.
    server.set_tsig_keys(make_tsig_key_map(config.tsig_keys));

    // Set up signal handling.
    let mut signals = set_up_signal_handling().context("failed to set up signal handling")?;

    // Start the I/O provider.
    info!("Set-up is complete; starting the server.");
    let thread_group = ThreadGroup::new();
    let server = Arc::new(server);
    let graceful_shutdown = io_provider.supports_graceful_shutdown();
    io_provider
        .start(&server, &thread_group)
        .context("failed to start the I/O provider")?;

    // Process incoming signals.
    for signal in signals.forever() {
        match signal {
            s @ (SIGINT | SIGTERM) => {
                let name = match s {
                    SIGINT => "SIGINT",
                    SIGTERM => "SIGTERM",
                    _ => unreachable!(),
                };
                info!("Received {}; shutting down.", name);
                break;
            }
            SIGHUP => {
                info!("Received SIGHUP; reloading zones and keys.");
                match reload_zones_and_keys(&reload_source, &server, &catalog) {
                    Ok(new_catalog) => catalog = new_catalog,
                    Err(e) => {
                        let mut message = String::from("Failed to reload zones and keys:");
                        for (i, cause) in e.chain().enumerate() {
                            write!(message, "\n[{}] {}", i + 1, cause).unwrap();
                        }
                        error!("{}", message);
                    }
                };
            }
            _ => unreachable!(),
        }
    }

    // Shut down the server.
    if graceful_shutdown {
        thread_group.shut_down();
        thread_group.await_shutdown();
        info!("Shutdown complete.");
    }
    Ok(())
}

fn configure_server(server: &mut Server, config: &ServerConfig) -> Result<()> {
    // Set the EDNS UDP payload size if it's configured.
    if let Some(size) = config.edns_udp_payload_size {
        server
            .set_edns_udp_payload_size(size)
            .context("failed to set the EDNS UDP payload size")?;
    }

    // Configure response rate-limiting (RRL) if it's enabled.
    if let Some(ref rrl_config) = config.rrl {
        configure_rrl(server, rrl_config).context("failed to configure RRL")?;
    }

    Ok(())
}

fn configure_rrl(server: &mut Server, config: &RrlConfig) -> Result<()> {
    let mut rrl_params = RrlParams::new(
        config.noerror_rate,
        config.nxdomain_rate,
        config.error_rate,
        config.window,
    )?;
    if let Some(slip) = config.slip {
        rrl_params.set_slip(slip);
    }
    if let Some(ipv4_prefix_len) = config.ipv4_prefix_len {
        rrl_params.set_ipv4_prefix_len(ipv4_prefix_len)?;
    }
    if let Some(ipv6_prefix_len) = config.ipv6_prefix_len {
        rrl_params.set_ipv6_prefix_len(ipv6_prefix_len)?;
    }
    if let Some(size) = config.size {
        rrl_params.set_size(size)?;
    }
    server.set_rrl_params(Some(rrl_params));
    Ok(())
}

fn make_tsig_key_map(tsig_keys: HashMap<Box<ConfigName>, TsigKeyConfig>) -> Arc<TsigKeyMap> {
    Arc::new(
        tsig_keys
            .into_iter()
            .map(|(name, config)| (name.0, (config.algorithm.into(), config.secret)))
            .collect(),
    )
}

fn set_up_signal_handling() -> Result<Signals> {
    let all_signals = &[SIGHUP, SIGINT, SIGTERM];
    let term_signals = &[SIGINT, SIGTERM];
    let already_terminating = Arc::new(AtomicBool::new(false));

    // This sets up signal handlers to exit immediately if a second
    // termination signal arrives before the process finishes shutting
    // down gracefully.
    for sig in term_signals {
        signal_hook::flag::register_conditional_shutdown(*sig, 1, already_terminating.clone())?;
        signal_hook::flag::register(*sig, already_terminating.clone())?;
    }

    Signals::new(all_signals).map_err(Into::into)
}

enum ReloadSource<'a> {
    Args(Vec<ZoneConfig>),
    Config(&'a Path),
}

fn reload_zones_and_keys(
    reload_source: &ReloadSource,
    server: &Server,
    catalog: &Catalog,
) -> Result<Arc<Catalog>> {
    let (zone_configs, tsig_keys) = match reload_source {
        ReloadSource::Args(zone_configs) => (zone_configs.clone(), HashMap::new()),
        ReloadSource::Config(path) => {
            let config =
                config::load_from_path(path, true).context("failed to reload the configuration")?;
            (config.zones, config.tsig_keys)
        }
    };
    let new_catalog = Arc::new(zones::reload(zone_configs, catalog));
    let new_tsig_key_map = make_tsig_key_map(tsig_keys);
    server.set_catalog(new_catalog.clone());
    server.set_tsig_keys(new_tsig_key_map);
    Ok(new_catalog)
}
