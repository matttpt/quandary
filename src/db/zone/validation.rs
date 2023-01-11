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

//! Implementation of zone validation, to detect semantic errors and
//! warnings in a loaded zone.
//!
//! [RFC 1035 § 5.2] (corrected by [Erratum 5626]) indicates that a zone
//! file should be checked for semantic errors in addition to syntactic
//! errors. The validity checks indicated are:
//!
//! 1. All RRs must have must same class.
//! 2. Exactly one SOA record should be present at the zone apex.
//! 3. Any required glue records must be present.
//! 4. Non-authoritative information must be glue information, not
//!    the result of a mistake.
//! 5. ([Erratum 5626]) At least one NS record must be present at the
//!    zone apex.
//!
//! Check 1 is enforced by the [`Zone`] API. Check 4 seems not to be
//! implemented in the BIND and Knot-DNS zone validators, and indeed
//! such "occluded" information may result from the installation of an
//! NS record through dynamic DNS updates (see paragraph 7.13 of
//! [RFC 2136]). Therefore, we do not implement it here. The remaining
//! checks are implemented in [`Zone::validate`]. (It should be noted
//! that check 3 is performed in accordance with the zone's
//! [`GluePolicy`](super::GluePolicy).)
//!
//! In addition, the following checks are also implemented in
//! [`Zone::validate`]:
//!
//!  6. A name cannot own more than one CNAME record.
//!  7. A name cannot own a CNAME record and another record of a
//!     different type.
//!  8. Any in-zone nameservers referenced by NS records must have A or
//!     AAAA records.
//!  9. Any in-zone mail exchangers referenced by MX records should have
//!     A or AAAA records (warning only).
//! 10. Wildcard domain names should not own NS records, since
//!     [RFC 4592 § 4.2] discourages this and leaves its semantics
//!     undefined (warning only).
//!
//! Finally, the following checks (in addition to RFC 1035's check 1)
//! are enforced by the design of the [`Zone`] API:
//!
//! 11. The owners of all records are at or below the zone apex.
//! 12. The TTL of each record in an RRset is the same (as required by
//!     [RFC 2181 § 5.2]).
//!
//! [RFC 1035 § 5.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-5.2
//! [Erratum 5626]: https://www.rfc-editor.org/errata/eid5626
//! [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
//! [RFC 2181 § 5.2]: https://datatracker.ietf.org/doc/html/rfc2181#section-5.2
//! [RFC 4592 § 4.2]: https://datatracker.ietf.org/doc/html/rfc4592#section-4.2

use std::collections::HashSet;
use std::fmt;

use crate::class::Class;
use crate::name::Name;
use crate::rr::Type;

use super::super::Error;
use super::{Addresses, Found, GluePolicy, IteratedRrset, LookupAddrsResult, LookupOptions, Zone};

////////////////////////////////////////////////////////////////////////
// VALIDATION ISSUES                                                  //
////////////////////////////////////////////////////////////////////////

/// Indicates a semantic error or warning found in a loaded zone.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ValidationIssue<'a> {
    MissingApexSoa,
    TooManyApexSoas,
    MissingApexNs,
    MissingNsAddress(Box<Name>),
    MissingMxAddress(Box<Name>),
    MissingGlue(Box<Name>),
    DuplicateCname(&'a Name),
    OtherRecordsAtCname(&'a Name),
    NsAtWildcard(&'a Name),
}

impl ValidationIssue<'_> {
    /// Returns whether the `ValidationIssue` represents a (fatal)
    /// error. Otherwise, it is a warning.
    pub fn is_error(&self) -> bool {
        !matches!(*self, Self::MissingMxAddress(_) | Self::NsAtWildcard(_))
    }
}

impl fmt::Display for ValidationIssue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::MissingApexSoa => f.write_str("the zone is missing an SOA record"),
            Self::TooManyApexSoas => {
                f.write_str("the zone has too many SOA records (precisely one is needed)")
            }
            Self::MissingApexNs => f.write_str("the zone is missing an NS record"),
            Self::MissingNsAddress(ref nsdname) => write!(
                f,
                "the in-zone nameserver {} is missing an address",
                nsdname
            ),
            Self::MissingMxAddress(ref name) => write!(
                f,
                "the in-zone mail exchanger {} is missing an address",
                name
            ),
            Self::MissingGlue(ref nsdname) => {
                write!(f, "a glue record for {} is needed", nsdname)
            }
            Self::DuplicateCname(name) => {
                write!(f, "the name {} has duplicate CNAME records", name)
            }
            Self::OtherRecordsAtCname(name) => write!(
                f,
                "the name {}, which has a CNAME record, cannot have other records",
                name
            ),
            Self::NsAtWildcard(name) => write!(
                f,
                "the wildcard domain name {} owns an NS RRset; \
                 this is discouraged and its semantics are undefined",
                name
            ),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// VALIDATION LOGIC                                                   //
////////////////////////////////////////////////////////////////////////

/// Implements zone validation; this does the real work of
/// [`Zone::validate`].
pub fn validate<Z>(zone: &Z) -> Result<Vec<ValidationIssue>, Error>
where
    Z: Zone + ?Sized,
{
    let mut issues = HashSet::new();

    // Check 2: there must be exactly one SOA record for the zone.
    if let Some(soa_rrset) = zone.soa() {
        if soa_rrset.rdatas.iter().count() != 1 {
            issues.insert(ValidationIssue::TooManyApexSoas);
        }
    } else {
        issues.insert(ValidationIssue::MissingApexSoa);
    }

    // Check 5: there must be at least one NS record for the zone.
    if let Some(ns_rrset) = zone.ns() {
        if class_has_addrs(zone.class()) {
            for rdata in ns_rrset.rdatas.iter() {
                // Part of check 8: nameservers for the zone must have
                // address records if they are within the zone.
                let name =
                    Name::try_from_uncompressed_all(rdata.octets()).or(Err(Error::InvalidRdata))?;
                check_apex_ns_address(zone, name, &mut issues);
            }
        }
    } else {
        issues.insert(ValidationIssue::MissingApexNs);
    }

    // Now, we scan the RRsets of the zone, which will perform the
    // remaining checks.
    for (owner, rrsets) in zone.iter_by_node() {
        scan_node(zone, owner, rrsets.collect(), &mut issues)?;
    }
    Ok(issues.into_iter().collect())
}

/// Scans a node, checking for semantic errors and warnings. This
/// implements checks 3 and 6 through 10.
fn scan_node<'a, Z>(
    zone: &Z,
    owner: &'a Name,
    rrsets: Vec<IteratedRrset>,
    issues: &mut HashSet<ValidationIssue<'a>>,
) -> Result<(), Error>
where
    Z: Zone + ?Sized,
{
    for rrset in rrsets.iter() {
        match rrset.rr_type {
            Type::CNAME => {
                // Perform CNAME checks (6 and 7).
                if rrsets.len() != 1 {
                    issues.insert(ValidationIssue::OtherRecordsAtCname(owner));
                }
                if rrset.rdatas.iter().count() != 1 {
                    issues.insert(ValidationIssue::DuplicateCname(owner));
                }
            }
            Type::MX => {
                if class_has_addrs(zone.class()) {
                    // Perform the MX address check (9).
                    for rdata in rrset.rdatas.iter() {
                        let name = rdata
                            .octets()
                            .get(2..)
                            .map(Name::try_from_uncompressed_all)
                            .and_then(Result::ok)
                            .ok_or(Error::InvalidRdata)?;
                        check_mx_address(zone, name, issues);
                    }
                }
            }
            Type::NS => {
                // Perform the NS-at-wildcard check (10).
                if owner.is_wildcard() {
                    issues.insert(ValidationIssue::NsAtWildcard(owner));
                }

                // Perform glue (3) and in-zone NS address (8) checks.
                // TODO: this currently checks occluded NS records,
                //       since the implementation is easier this way.
                //       But should we omit them?
                let at_apex = owner.len() == zone.name().len();
                if !at_apex && class_has_addrs(zone.class()) {
                    for rdata in rrset.rdatas.iter() {
                        let nsdname = Name::try_from_uncompressed_all(rdata.octets())
                            .or(Err(Error::InvalidRdata))?;
                        check_delegation_ns_address(zone, nsdname, owner, issues);
                    }
                }
            }
            _ => (),
        }
    }
    Ok(())
}

/// Ensures that, if an apex NS record specifies a nameserver whose name
/// is in the zone, an address record for it is present (check 8).
fn check_apex_ns_address<Z>(zone: &Z, nsdname: Box<Name>, issues: &mut HashSet<ValidationIssue>)
where
    Z: Zone + ?Sized,
{
    match zone.lookup_addrs(&nsdname, LookupOptions::default()) {
        LookupAddrsResult::Found(found) => {
            if !addrs_found(zone.class(), &found) {
                issues.insert(ValidationIssue::MissingNsAddress(nsdname));
            }
        }
        LookupAddrsResult::Cname(_) | LookupAddrsResult::NxDomain => {
            issues.insert(ValidationIssue::MissingNsAddress(nsdname));
        }
        LookupAddrsResult::Referral(_) | LookupAddrsResult::WrongZone => (),
    }
}

/// Ensures that, if required, `parent_zone` has an in-zone address
/// record or glue record for `child_zone`'s nameserver `nsdname`
/// specified in a delegation NS record (checks 3 and 8).
fn check_delegation_ns_address<Z>(
    parent_zone: &Z,
    nsdname: Box<Name>,
    child_zone: &Name,
    issues: &mut HashSet<ValidationIssue>,
) where
    Z: Zone + ?Sized,
{
    match parent_zone.lookup_addrs(&nsdname, LookupOptions::default()) {
        LookupAddrsResult::Found(found) => {
            // A glue record is not necessary, since nsdname is within
            // the parent zone itself. However, we ought to make sure
            // that the parent zone actually has addresses for the
            // nameserver! (This is check 8.)
            if !addrs_found(parent_zone.class(), &found) {
                issues.insert(ValidationIssue::MissingNsAddress(nsdname));
            }
        }
        LookupAddrsResult::Referral(referral) => {
            // The nameserver for the delegation is inside some child
            // zone (referral.child_zone) of parent_zone. Whether we
            // require glue depends on parent_zone's glue policy. (This
            // is check 3.)
            match parent_zone.glue_policy() {
                GluePolicy::Wide => {
                    // Glue is always needed.
                    check_glue(parent_zone, nsdname, issues);
                }
                GluePolicy::Narrow => {
                    // Glue is needed only if the child zone in which
                    // the nameserver resides is child_zone.
                    if referral.child_zone.as_ref() == child_zone {
                        check_glue(parent_zone, nsdname, issues);
                    }
                }
            }
        }
        LookupAddrsResult::Cname(_) | LookupAddrsResult::NxDomain => {
            // Same as the LookupAddrsResult::Found case, except that we
            // know immediately that the parent zone lacks an address
            // for the nameserver.
            issues.insert(ValidationIssue::MissingNsAddress(nsdname));
        }
        LookupAddrsResult::WrongZone => {
            // A glue record is not necessary, since nsdname is outside
            // the parent zone's hierarchy.
        }
    }
}

/// Checks that `parent_zone` contains a glue record for a child zone's
/// nameserver `nsdname`.
fn check_glue<Z>(parent_zone: &Z, nsdname: Box<Name>, issues: &mut HashSet<ValidationIssue>)
where
    Z: Zone + ?Sized,
{
    let lookup_options = LookupOptions {
        unchecked: false,
        search_below_cuts: true,
    };
    match parent_zone.lookup_addrs(&nsdname, lookup_options) {
        LookupAddrsResult::Found(found) => {
            if !addrs_found(parent_zone.class(), &found) {
                issues.insert(ValidationIssue::MissingGlue(nsdname));
            }
        }
        _ => {
            issues.insert(ValidationIssue::MissingGlue(nsdname));
        }
    }
}

/// Ensures that, if an MX record specifies a mail exchanger whose name
/// is in the zone, an address record for it is present (check 9).
fn check_mx_address<Z>(zone: &Z, name: Box<Name>, issues: &mut HashSet<ValidationIssue>)
where
    Z: Zone + ?Sized,
{
    match zone.lookup_addrs(&name, LookupOptions::default()) {
        LookupAddrsResult::Found(found) => {
            if !addrs_found(zone.class(), &found) {
                issues.insert(ValidationIssue::MissingMxAddress(name));
            }
        }
        LookupAddrsResult::Cname(_) | LookupAddrsResult::NxDomain => {
            issues.insert(ValidationIssue::MissingMxAddress(name));
        }
        LookupAddrsResult::Referral(_) | LookupAddrsResult::WrongZone => (),
    }
}

/// Returns whether address RR types are defined for a class.
fn class_has_addrs(class: Class) -> bool {
    class == Class::IN || class == Class::CH
}

/// Determines whether an address lookup found at least one acceptable
/// address.
fn addrs_found(class: Class, found: &Found<Addresses>) -> bool {
    found.data.a_rrset.is_some() || (class == Class::IN && found.data.aaaa_rrset.is_some())
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::super::{GluePolicy, Zone};
    use super::ValidationIssue;
    use crate::class::Class;
    use crate::db::HashMapTreeZone;
    use crate::name::Name;
    use crate::rr::{Rdata, Ttl, Type};

    lazy_static! {
        static ref APEX: Box<Name> = "quandary.test.".parse().unwrap();
        static ref NS: Box<Name> = "ns.quandary.test.".parse().unwrap();
        static ref MX: Box<Name> = "mx.quandary.test.".parse().unwrap();
        static ref HOST1: Box<Name> = "HOST1.quandary.test.".parse().unwrap();
        static ref HOST2: Box<Name> = "HOST2.quandary.test.".parse().unwrap();
        static ref HOST3: Box<Name> = "HOST3.quandary.test.".parse().unwrap();
        static ref SUBDEL: Box<Name> = "subdel.quandary.test.".parse().unwrap();
        static ref NS_SUBDEL: Box<Name> = "ns.subdel.quandary.test.".parse().unwrap();
        static ref SUBDEL2: Box<Name> = "subdel2.quandary.test.".parse().unwrap();
        static ref WILDCARD: Box<Name> = "*.quandary.test.".parse().unwrap();
        static ref APEX_SOA_RDATA: &'static Rdata = b"\
                \x02ns\x08quandary\x04test\x00\
                \x08hostmaster\x08quandary\x04test\x00\
                \x00\x00\x00\x00\
                \x00\x00\x00\x00\
                \x00\x00\x00\x00\
                \x00\x00\x00\x00\
                \x00\x00\x00\x00"
            .try_into()
            .unwrap();
        static ref APEX_SOA_RDATA2: &'static Rdata = b"\
                \x02ns\x08quandary\x04test\x00\
                \x08hostmaster\x08quandary\x04test\x00\
                \xff\xff\xff\xff\
                \xff\xff\xff\xff\
                \xff\xff\xff\xff\
                \xff\xff\xff\xff\
                \xff\xff\xff\xff"
            .try_into()
            .unwrap();
        static ref APEX_NS_RDATA: &'static Rdata = NS.wire_repr().try_into().unwrap();
        static ref APEX_MX_RDATA: &'static Rdata = b"\x00\x0a\x02mx\x08quandary\x04test\x00"
            .try_into()
            .unwrap();
        static ref LOCALHOST_RDATA: &'static Rdata = b"\x7f\x00\x00\x00".try_into().unwrap();
        static ref SUBDEL_NS_RDATA: &'static Rdata = NS_SUBDEL.wire_repr().try_into().unwrap();
    }

    fn add_rr(zone: &mut HashMapTreeZone, owner: &Name, rr_type: Type, rdata: &Rdata) {
        zone.add(owner, rr_type, Class::IN, Ttl::from(3600), rdata)
            .unwrap();
    }

    fn add_basic_rrs(zone: &mut HashMapTreeZone) {
        add_rr(zone, &APEX, Type::SOA, &APEX_SOA_RDATA);
        add_rr(zone, &APEX, Type::NS, &APEX_NS_RDATA);
        add_rr(zone, &NS, Type::A, &LOCALHOST_RDATA);
    }

    #[test]
    fn validate_detects_missing_apex_soa() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::NS, &APEX_NS_RDATA);
        add_rr(&mut zone, &NS, Type::A, &LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingApexSoa],
        );
    }

    #[test]
    fn validate_detects_too_many_soas() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, &APEX_SOA_RDATA);
        add_rr(&mut zone, &APEX, Type::SOA, &APEX_SOA_RDATA2);
        add_rr(&mut zone, &APEX, Type::NS, &APEX_NS_RDATA);
        add_rr(&mut zone, &NS, Type::A, &LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::TooManyApexSoas],
        );
    }

    #[test]
    fn validate_detects_missing_glue() {
        // Narrow glue policy when the nameserver is within the child
        // zone: there should be an error.
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, &SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            [ValidationIssue::MissingGlue(NS_SUBDEL.clone())],
        );

        // Narrow glue policy when the nameserver is within a different
        // child zone: there should not be an error.
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, &APEX_NS_RDATA);
        add_rr(&mut zone, &SUBDEL2, Type::NS, &SUBDEL_NS_RDATA);
        assert_eq!(zone.validate().unwrap(), []);

        // Wide glue policy when the nameserver is within a different
        // child zone: there should still be an error.
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Wide);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, &APEX_NS_RDATA);
        add_rr(&mut zone, &SUBDEL2, Type::NS, &SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            [ValidationIssue::MissingGlue(NS_SUBDEL.clone())],
        );
    }

    #[test]
    fn validate_detects_missing_apex_ns() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, &APEX_SOA_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingApexNs],
        );
    }

    #[test]
    fn validate_detects_multiple_cname() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(
            &mut zone,
            &HOST1,
            Type::CNAME,
            HOST2.wire_repr().try_into().unwrap(),
        );
        add_rr(
            &mut zone,
            &HOST1,
            Type::CNAME,
            HOST3.wire_repr().try_into().unwrap(),
        );
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::DuplicateCname(&HOST1)],
        );
    }

    #[test]
    fn validate_detects_other_records_at_cname() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(
            &mut zone,
            &HOST1,
            Type::CNAME,
            HOST2.wire_repr().try_into().unwrap(),
        );
        add_rr(&mut zone, &HOST1, Type::A, &LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::OtherRecordsAtCname(&HOST1)],
        );
    }

    #[test]
    fn validate_detects_missing_ns_address() {
        // First case: the apex NS record is missing an address.
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, &APEX_SOA_RDATA);
        add_rr(&mut zone, &APEX, Type::NS, &APEX_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingNsAddress(NS.clone())],
        );

        // Second case: a delegation NS record which points to a name
        // within the zone is missing an address.
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL2, Type::NS, &SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingNsAddress(NS_SUBDEL.clone())],
        );
    }

    #[test]
    fn validate_detects_missing_mx_address() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &APEX, Type::MX, &APEX_MX_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingMxAddress(MX.clone())],
        );
    }

    #[test]
    fn validate_detects_ns_at_wildcard() {
        let mut zone = HashMapTreeZone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &NS_SUBDEL, Type::A, &LOCALHOST_RDATA);
        add_rr(&mut zone, &WILDCARD, Type::NS, &SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::NsAtWildcard(&WILDCARD)],
        );
    }
}
