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

//! Implements zone loading.

use std::fmt::Write;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use log::Level::Warn;
use log::{debug, error, log_enabled, warn};

use quandary::db::zone::ValidationIssue;
use quandary::db::{Catalog as _, HashMapTreeCatalog, HashMapTreeZone, Zone};
use quandary::zone_file::fs::Parser;

use crate::config::ZoneConfig;

/// The specific [`HashMapTreeCatalog`] type that we use.
pub type Catalog = HashMapTreeCatalog<HashMapTreeZone, Metadata>;

/// The specific catalog [`Entry`](quandary::db::catalog::Entry) type
/// that we use.
type Entry = quandary::db::catalog::Entry<HashMapTreeZone, Metadata>;

/// The zone metadata that we store in each catalog entry.
#[derive(Clone)]
pub struct Metadata {
    path: PathBuf,
    mtime: Option<SystemTime>,
}

/// The maximum number of nested `$INCLUDE` directives that we will
/// process before raising an error.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Loads the zones configured in `zones`.
pub fn load(zones: Vec<ZoneConfig>) -> Catalog {
    load_impl(zones, None)
}

/// Reloads the zones configured in `zones`. For each zone, if the zone
/// is currently loaded (in the catalog `loaded`) and has not changed
/// on disk, then the currently loaded zone will be reused.
pub fn reload(zones: Vec<ZoneConfig>, loaded: &Catalog) -> Catalog {
    load_impl(zones, Some(loaded))
}

/// The implementation of [`load`] and [`reload`].
fn load_impl(zones: Vec<ZoneConfig>, loaded: Option<&Catalog>) -> Catalog {
    let mut catalog = Catalog::new();
    let mut zones_failed = 0;

    for zone_config in zones {
        // Determine whether the zone should be (re)loaded.
        let loaded_zone = loaded.and_then(|c| c.lookup(&zone_config.name.0, zone_config.class.0));
        let (mtime, zone_config) = match check_mtime(zone_config, loaded_zone) {
            MtimeCheckResult::Load { mtime, zone_config } => (mtime, zone_config),
            MtimeCheckResult::Skip { entry } => {
                catalog.insert(entry);
                continue;
            }
        };

        // Load and validate the zone.
        debug!(
            "Loading {}/{} from {}.",
            zone_config.name.0,
            zone_config.class.0,
            zone_config.path.display(),
        );
        match load_and_validate_zone(&zone_config) {
            Ok(zone) => {
                catalog.insert(Entry::Loaded(
                    Arc::new(zone),
                    Metadata {
                        path: zone_config.path,
                        mtime,
                    },
                ));
            }
            Err(e) => {
                let mut message = format!(
                    "Failed to load {}/{}:",
                    zone_config.name.0, zone_config.class.0
                );
                for (i, cause) in e.chain().enumerate() {
                    write!(message, "\n[{}] {}", i + 1, cause).unwrap();
                }
                error!("{}", message);
                catalog.insert(make_error_catalog_entry(zone_config, loaded_zone));
                zones_failed += 1;
            }
        }
    }

    if zones_failed > 0 {
        if zones_failed == 1 {
            error!("1 zone failed to load.");
        } else {
            error!("{} zones failed to load.", zones_failed);
        }
    }

    catalog
}

/// The result of [`check_mtime`], indicating whether a zone should be
/// (re)loaded from disk.
enum MtimeCheckResult {
    Load {
        mtime: Option<SystemTime>,
        zone_config: ZoneConfig,
    },
    Skip {
        entry: Entry,
    },
}

/// Checks the modification time of a zone's file. comapring it to the
/// time the zone was last loaded (if any). Returns what action to take
/// (see [`MtimeCheckResult`]).
fn check_mtime(zone_config: ZoneConfig, loaded_zone: Option<&Entry>) -> MtimeCheckResult {
    match fs::metadata(&zone_config.path).and_then(|m| m.modified()) {
        Ok(mtime) => match loaded_zone {
            Some(Entry::Loaded(zone, metadata)) => {
                if metadata.path == zone_config.path
                    && metadata
                        .mtime
                        .map(|loaded_mtime| mtime <= loaded_mtime)
                        .unwrap_or(false)
                {
                    debug!(
                        "Skipping load of {}/{}: \
                         the zone file {} has not changed since it was last loaded.",
                        zone_config.name.0,
                        zone_config.class.0,
                        zone_config.path.display(),
                    );
                    MtimeCheckResult::Skip {
                        entry: Entry::Loaded(zone.clone(), metadata.clone()),
                    }
                } else {
                    MtimeCheckResult::Load {
                        mtime: Some(mtime),
                        zone_config,
                    }
                }
            }
            _ => MtimeCheckResult::Load {
                mtime: Some(mtime),
                zone_config,
            },
        },
        Err(e) if e.kind() != ErrorKind::Unsupported => {
            error!(
                "Failed to get metadata for {}: {}. The zone {}/{} will not be loaded.",
                zone_config.path.display(),
                e,
                zone_config.name.0,
                zone_config.class.0,
            );
            MtimeCheckResult::Skip {
                entry: make_error_catalog_entry(zone_config, loaded_zone),
            }
        }
        _ => MtimeCheckResult::Load {
            mtime: None,
            zone_config,
        },
    }
}

/// Loads and validates a single zone.
fn load_and_validate_zone(zone_config: &ZoneConfig) -> Result<HashMapTreeZone> {
    let mut zone = HashMapTreeZone::new(
        zone_config.name.0.clone(),
        zone_config.class.0,
        zone_config.glue_policy.into(),
    );
    let parser = Parser::open(&zone_config.path, MAX_INCLUDE_DEPTH)
        .with_context(|| format!("failed to open {}", zone_config.path.display()))?;
    for line in parser {
        let line =
            line.with_context(|| format!("failed to parse {}", zone_config.path.display()))?;
        zone.add(
            &line.record.owner,
            line.record.rr_type,
            line.record.class,
            line.record.ttl,
            &line.record.rdata,
        )
        .with_context(|| {
            format!(
                "failed to add the record at {} line {} to the zone",
                line.path.display(),
                line.number,
            )
        })?;
    }

    validate_zone(&zone).and(Ok(zone))
}

/// Validates a loaded zone. Errors and warnings are written to the log.
/// Returns whether the zone is free of errors (but not warnings).
fn validate_zone(zone: &HashMapTreeZone) -> Result<()> {
    let issues = zone
        .validate()
        .context("failed to run the validator on the zone")?;
    if issues.is_empty() {
        return Ok(());
    }

    // If we're here, there are issues to report. The rest of this
    // function is devoted to displaying them properly.
    let have_errors = issues.iter().any(ValidationIssue::is_error);
    let have_warnings = !issues.iter().all(ValidationIssue::is_error);
    let mut message = String::new();

    // Display the header.
    if have_errors {
        write!(
            message,
            "Validation of {}/{} failed for the following reasons:",
            zone.name(),
            zone.class(),
        )
        .unwrap();
    } else if log_enabled!(Warn) {
        write!(
            message,
            "Validation of {}/{} produced the following warnings:",
            zone.name(),
            zone.class(),
        )
        .unwrap();
    }

    // List the issues.
    if have_errors || log_enabled!(Warn) {
        for (i, issue) in issues.iter().enumerate() {
            if have_errors && have_warnings {
                if issue.is_error() {
                    write!(message, "\n[{}] (error) {}", i + 1, issue).unwrap();
                } else {
                    write!(message, "\n[{}] (warning) {}", i + 1, issue).unwrap();
                }
            } else {
                write!(message, "\n[{}] {}", i + 1, issue).unwrap();
            }
        }
    }

    // Produce the final verdict.
    if have_errors {
        if have_warnings {
            message
                .push_str("\nItems marked \"error\" must be fixed before the zone can be loaded.");
        } else {
            message.push_str("\nAll items above must be fixed before the zone can be loaded.");
        }
        error!("{}", message);
        Err(anyhow!("zone validation failed (see above)"))
    } else if log_enabled!(Warn) {
        write!(
            message,
            "\nDespite these warnings, {}/{} will still be loaded.",
            zone.name(),
            zone.class(),
        )
        .unwrap();
        warn!("{}", message);
        Ok(())
    } else {
        Ok(())
    }
}

/// Makes a catalog entry for a zone that has failed to load. The
/// currently loaded entry is used if possible; this way, currently
/// loaded zones remain loaded (with the old data) if the new data fails
/// to load.
fn make_error_catalog_entry(zone_config: ZoneConfig, loaded: Option<&Entry>) -> Entry {
    loaded.map(Entry::clone).unwrap_or_else(|| {
        Entry::FailedToLoad(
            zone_config.name.0,
            zone_config.class.0,
            Metadata {
                path: zone_config.path,
                mtime: None,
            },
        )
    })
}
