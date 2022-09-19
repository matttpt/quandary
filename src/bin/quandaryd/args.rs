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

//! Implements command-line argument parsing.

use std::ffi::OsStr;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::anyhow;
use clap::{ArgGroup, Parser, Subcommand};

use quandary::name::Name;

/// Parses the command line arguemnts.
pub fn parse() -> Args {
    Args::parse()
}

/// The Quandary authoritative DNS server
#[derive(Debug, Parser)]
#[clap(author, version)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the server
    Run(RunArgs),
}

#[derive(Debug, Parser)]
#[clap(group(ArgGroup::new("required").required(true).args(&["config", "zones"])))]
pub struct RunArgs {
    /// Set the configuration file to use
    #[clap(long, conflicts_with_all=&["bind", "ip", "port"], value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Set the server bind IP address and port
    #[clap(long, value_name = "IP:PORT")]
    pub bind: Option<SocketAddr>,

    /// Set the server bind IP address
    #[clap(long, conflicts_with = "bind", value_name = "IP")]
    pub ip: Option<IpAddr>,

    /// Set the server port
    #[clap(long, conflicts_with = "bind", value_name = "PORT")]
    pub port: Option<u16>,

    /// Add zones to serve
    #[clap(
        long,
        multiple_values = true,
        use_value_delimiter = true,
        value_name = "FILE|NAME:FILE",
        value_parser
    )]
    pub zones: Vec<ZoneDescription>,
}

/// A description of a zone provided on the command line with the
/// `--zone` option. This is parsed with its [`FromStr`] implementation
/// and accepts two forms, one of which allows the zone apex to be given
/// explicitly, and the other of which infers the zone apex by stripping
/// the `.zone` suffix from the basename of the path to the zone file:
///
/// * `example.com.:path/to/the-zone-file.zone`
/// * `path/to/example.com.zone`
#[derive(Clone, Debug)]
pub struct ZoneDescription {
    pub name: Box<Name>,
    pub path: PathBuf,
}

impl FromStr for ZoneDescription {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((name, path)) = s.split_once(':') {
            Ok(Self {
                name: name
                    .parse()
                    .map_err(|e| anyhow!("invalid zone name: {}", e))?,
                path: PathBuf::from(path),
            })
        } else if s.ends_with(".zone") {
            if let Some(zone_name_without_trailing_dot) =
                Path::new(s).file_stem().and_then(OsStr::to_str)
            {
                Ok(Self {
                    name: format!("{}.", zone_name_without_trailing_dot)
                        .parse()
                        .map_err(|e| anyhow!("invalid zone name: {}", e))?,
                    path: PathBuf::from(s),
                })
            } else {
                Err(anyhow!("failed to compute zone name from zone file path"))
            }
        } else {
            Err(anyhow!(
                "if no zone name is provided, the file name must have the form <NAME>.zone",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_description_from_str_computes_zone_name_from_path_correctly() {
        let path =
            PathBuf::from_iter(["path_to", "a", "..", "zone_file", ".", "quandary.test.zone"]);
        let description: ZoneDescription = path.to_str().unwrap().parse().unwrap();
        assert_eq!(description.name, "quandary.test.".parse().unwrap());
    }
}
