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
use std::fs::File;

use anyhow::{anyhow, Context, Result};
use log::Level::Warn;
use log::{debug, error, log_enabled, warn};

use quandary::zone::{Catalog, CatalogEntry, ValidationIssue, Zone};
use quandary::zone_file::Parser;

use crate::config::ZoneConfig;

/// Loads the zones configured in `zones`.
pub fn load(zones: Vec<ZoneConfig>) -> Catalog {
    let mut catalog = Catalog::new();
    let mut zones_failed = 0;

    for zone_config in zones {
        debug!(
            "Loading {}/{} from {}.",
            zone_config.name.0,
            zone_config.class.0,
            zone_config.path.display(),
        );
        match load_and_validate_zone(&zone_config) {
            Ok(zone) => {
                catalog.replace(CatalogEntry::Loaded(zone));
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
                catalog.replace(CatalogEntry::FailedToLoad(
                    zone_config.name.0,
                    zone_config.class.0,
                ));
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

/// Loads and validates a single zone.
fn load_and_validate_zone(zone_config: &ZoneConfig) -> Result<Zone> {
    let mut zone = Zone::new(
        zone_config.name.0.clone(),
        zone_config.class.0,
        zone_config.glue_policy.into(),
    );
    let zone_file = File::open(&zone_config.path)
        .with_context(|| format!("failed to open {}", zone_config.path.display()))?;

    for line in Parser::new(zone_file).records_only() {
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
                zone_config.path.display(),
                line.number,
            )
        })?;
    }

    validate_zone(&zone).and(Ok(zone))
}

/// Validates a loaded zone. Errors and warnings are written to the log.
/// Returns whether the zone is free of errors (but not warnings).
fn validate_zone(zone: &Zone) -> Result<()> {
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
