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
//! Check 1 is handled when records are added with [`Zone::add`]. Check
//! 4 seems not to be implemented in the BIND and Knot-DNS zone
//! validators, and indeed such "occluded" information may result from
//! the installation of an NS record through dynamic DNS updates (see
//! paragraph 7.13 of [RFC 2136]). Therefore, we do not implement it
//! here. The remaining checks are implemented in [Zone::validate].
//! (It should be noted that check 3 is performed in accordance with the
//! zone's [`GluePolicy`](super::GluePolicy).)
//!
//! In addition, the following checks are also implemented in
//! [`Zone::validate`]:
//!
//! 6. A name cannot own more than one CNAME record.
//! 7. A name cannot own a CNAME record and another record of a
//!    different type.
//! 8. Any in-zone nameservers referenced by NS records must have A or
//!    AAAA records.
//! 9. Any in-zone mail exchangers referenced by MX records should have
//!    A or AAAA records (warning only).
//!
//! Finally, the following checks (in addition to RFC 1035's check 1)
//! are enforced by [`Zone::add`], since the [`Zone`] data structure
//! (and the [`Rrset`](crate::rr::Rrset)s it contains) cannot represent a
//! zone with these errors:
//!
//! 10. The owners of all records are at or below the zone apex.
//! 11. The TTL of each record in an RRset is the same (as required by
//!     [RFC 2181 § 5.2]).
//!
//! [RFC 1035 § 5.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-5.2
//! [Erratum 5626]: https://www.rfc-editor.org/errata/eid5626
//! [RFC 2136]: https://datatracker.ietf.org/doc/html/rfc2136
//! [RFC 2181 § 5.2]: https://datatracker.ietf.org/doc/html/rfc2181#section-5.2

use std::fmt;

use crate::name::Name;
use crate::rr::{RrsetList, Type};

use super::{Error, GluePolicy, LookupAllResult, Node, Zone};

////////////////////////////////////////////////////////////////////////
// VALIDATION ISSUES                                                  //
////////////////////////////////////////////////////////////////////////

/// Indicates a semantic error or warning found in a loaded zone.
#[derive(Debug, Eq, PartialEq)]
pub enum ValidationIssue<'a> {
    MissingApexSoa,
    TooManyApexSoas,
    MissingApexNs,
    MissingNsAddress(Box<Name>),
    MissingMxAddress(Box<Name>),
    MissingGlue(Box<Name>),
    DuplicateCname(&'a Name),
    OtherRecordsAtCname(&'a Name),
}

impl ValidationIssue<'_> {
    /// Returns whether the `ValidationIssue` represents a (fatal)
    /// error. Otherwise, it is a warning.
    pub fn is_error(&self) -> bool {
        !matches!(*self, Self::MissingMxAddress(_))
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
        }
    }
}

////////////////////////////////////////////////////////////////////////
// VALIDATION LOGIC                                                   //
////////////////////////////////////////////////////////////////////////

impl Zone {
    /// Checks a zone for semantic errors and warnings (other than those
    /// that are caught in [`Zone::add`]).
    ///
    /// The checks that are implemented here are checks 2, 3, 5, 6, 7,
    /// and 8 listed in the documentation for the `validation` module.
    pub fn validate(&self) -> Result<Vec<ValidationIssue>, Error> {
        let mut issues = Vec::new();

        // Check 2: there must be exactly one SOA record for the zone.
        if let Some(soa_rrset) = self.soa() {
            if soa_rrset.rdatas().count() != 1 {
                issues.push(ValidationIssue::TooManyApexSoas);
            }
        } else {
            issues.push(ValidationIssue::MissingApexSoa);
        }

        // Check 5: there must be at least one NS record for the zone.
        if let Some(ns_rrset) = self.ns() {
            for rdata in ns_rrset.rdatas() {
                // Part of check 8: nameservers for the zone must have
                // address records if they are within the zone.
                let name =
                    Name::try_from_uncompressed_all(rdata.octets()).or(Err(Error::InvalidRdata))?;
                check_apex_ns_address(self, name, &mut issues);
            }
        } else {
            issues.push(ValidationIssue::MissingApexNs);
        }

        // Now, we scan the nodes of the zone, which will perform CNAME
        // checks (6 and 7), NS address/glue checks (3 and 8), and
        // MX address checks (11) at the appropriate nodes.
        scan_zone(self, &mut issues)?;
        Ok(issues)
    }
}

/// Helper to start a recursive scan an entire zone with [`scan_node`].
fn scan_zone<'a>(zone: &'a Zone, issues: &mut Vec<ValidationIssue<'a>>) -> Result<(), Error> {
    scan_node(zone, &zone.apex, true, true, issues)
}

/// Scans a node, checking for semantic errors and warnings. After
/// checking the current node, all of its children are scanned. This
/// implements checks 3, 6, 7, and 8.
fn scan_node<'a>(
    zone: &'a Zone,
    node: &'a Node,
    at_apex: bool,
    in_authoritative: bool,
    issues: &mut Vec<ValidationIssue<'a>>,
) -> Result<(), Error> {
    // Perform CNAME checks (6 and 7).
    if let Some(cname_rrset) = node.rrsets.lookup(Type::CNAME) {
        if node.rrsets.len() != 1 {
            issues.push(ValidationIssue::OtherRecordsAtCname(&node.name));
        }
        if cname_rrset.rdatas().count() != 1 {
            issues.push(ValidationIssue::DuplicateCname(&node.name));
        }
    }

    // Perform the MX address check (9).
    if let Some(mx_rrset) = node.rrsets.lookup(Type::MX) {
        for rdata in mx_rrset.rdatas() {
            let name = rdata
                .octets()
                .get(2..)
                .map(Name::try_from_uncompressed_all)
                .and_then(Result::ok)
                .ok_or(Error::InvalidRdata)?;
            check_mx_address(zone, name, issues);
        }
    }

    // Perform glue (3) and in-zone NS address (8) checks.
    // TODO: should we also check occluded NS records, or just NS
    //       records currently in authoritative data as we do now?
    let at_delegation_point;
    if !at_apex && in_authoritative {
        if let Some(ns_rrset) = node.rrsets.lookup(Type::NS) {
            at_delegation_point = false;
            for rdata in ns_rrset.rdatas() {
                let nsdname =
                    Name::try_from_uncompressed_all(rdata.octets()).or(Err(Error::InvalidRdata))?;
                check_delegation_ns_address(zone, nsdname, &node.name, issues);
            }
        } else {
            at_delegation_point = true;
        }
    } else {
        at_delegation_point = true;
    }

    for child in node.children.values() {
        scan_node(zone, child, false, at_delegation_point, issues)?;
    }
    Ok(())
}

/// Ensures that, if an apex NS record specifies a nameserver whose name
/// is in the zone, an address record for it is present (check 8).
fn check_apex_ns_address(zone: &Zone, nsdname: Box<Name>, issues: &mut Vec<ValidationIssue>) {
    match zone.lookup_all(&nsdname) {
        LookupAllResult::Found(found) => {
            if !has_address(found.rrsets) {
                issues.push(ValidationIssue::MissingNsAddress(nsdname));
            }
        }
        LookupAllResult::WrongZone | LookupAllResult::Referral(_) => (),
        LookupAllResult::NxDomain => issues.push(ValidationIssue::MissingNsAddress(nsdname)),
    }
}

/// Ensures that, if required, `parent_zone` has an in-zone address
/// record or glue record for `child_zone`'s nameserver `nsdname`
/// specified in a delegation NS record (checks 3 and 8).
fn check_delegation_ns_address(
    parent_zone: &Zone,
    nsdname: Box<Name>,
    child_zone: &Name,
    issues: &mut Vec<ValidationIssue>,
) {
    match parent_zone.lookup_all(&nsdname) {
        LookupAllResult::Found(found) => {
            // A glue record is not necessary, since nsdname is within
            // the parent zone itself. However, we ought to make sure
            // that the parent zone actually has addresses for the
            // nameserver! (This is check 8.)
            if !has_address(found.rrsets) {
                issues.push(ValidationIssue::MissingNsAddress(nsdname));
            }
        }
        LookupAllResult::Referral(referral) => {
            // The nameserver for the delegation is inside some child
            // zone (referral.child_zone) of parent_zone. Whether we
            // require glue depends on parent_zone's glue policy. (This
            // is check 3.)
            match parent_zone.glue_policy {
                GluePolicy::Wide => {
                    // Glue is always needed.
                    check_glue(parent_zone, nsdname, issues);
                }
                GluePolicy::Narrow => {
                    // Glue is needed only if the child zone in which
                    // the nameserver resides is child_zone.
                    if referral.child_zone == child_zone {
                        check_glue(parent_zone, nsdname, issues);
                    }
                }
            }
        }
        LookupAllResult::WrongZone => {
            // A glue record is not necessary, since nsdname is outside
            // the parent zone's hierarchy.
        }
        LookupAllResult::NxDomain => {
            // Same as the LookupAllResult::Found case, except that we
            // know immediately that the parent zone lacks an address
            // for the nameserver.
            issues.push(ValidationIssue::MissingNsAddress(nsdname));
        }
    }
}

/// Checks that `parent_zone` contains a glue record for a child zone's
/// nameserver `nsdname`.
fn check_glue(parent_zone: &Zone, nsdname: Box<Name>, issues: &mut Vec<ValidationIssue>) {
    match parent_zone.lookup_all_raw(&nsdname, false) {
        LookupAllResult::Found(found) => {
            if !has_address(found.rrsets) {
                issues.push(ValidationIssue::MissingGlue(nsdname));
            }
        }
        _ => issues.push(ValidationIssue::MissingGlue(nsdname)),
    }
}

/// Ensures that, if an MX record specifies a mail exchanger whose name
/// is in the zone, an address record for it is present (check 9).
fn check_mx_address(zone: &Zone, name: Box<Name>, issues: &mut Vec<ValidationIssue>) {
    match zone.lookup_all(&name) {
        LookupAllResult::Found(found) => {
            if !has_address(found.rrsets) {
                issues.push(ValidationIssue::MissingMxAddress(name));
            }
        }
        LookupAllResult::WrongZone | LookupAllResult::Referral(_) => (),
        LookupAllResult::NxDomain => issues.push(ValidationIssue::MissingMxAddress(name)),
    }
}

/// Helper to determine whether an [`RrsetList`] contains an address
/// RRset (i.e., an A or AAAA RRset).
fn has_address(rrsets: &RrsetList) -> bool {
    for rrset in rrsets.iter() {
        if rrset.rr_type == Type::A || rrset.rr_type == Type::AAAA {
            return true;
        }
    }
    false
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

    fn add_rr(zone: &mut Zone, owner: &Name, rr_type: Type, rdata: &Rdata) {
        zone.add(owner, rr_type, Class::IN, Ttl::from(3600), rdata)
            .unwrap();
    }

    fn add_basic_rrs(zone: &mut Zone) {
        add_rr(zone, &APEX, Type::SOA, *APEX_SOA_RDATA);
        add_rr(zone, &APEX, Type::NS, *APEX_NS_RDATA);
        add_rr(zone, &NS, Type::A, *LOCALHOST_RDATA);
    }

    #[test]
    fn validate_detects_missing_apex_soa() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::NS, *APEX_NS_RDATA);
        add_rr(&mut zone, &NS, Type::A, *LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingApexSoa]
        );
    }

    #[test]
    fn validate_detects_too_many_soas() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, *APEX_SOA_RDATA);
        add_rr(&mut zone, &APEX, Type::SOA, *APEX_SOA_RDATA2);
        add_rr(&mut zone, &APEX, Type::NS, *APEX_NS_RDATA);
        add_rr(&mut zone, &NS, Type::A, *LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::TooManyApexSoas]
        );
    }

    #[test]
    fn validate_detects_missing_glue() {
        // Narrow glue policy when the nameserver is within the child
        // zone: there should be an error.
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, *SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            [ValidationIssue::MissingGlue(NS_SUBDEL.clone())]
        );

        // Narrow glue policy when the nameserver is within a different
        // child zone: there should not be an error.
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, *APEX_NS_RDATA);
        add_rr(&mut zone, &SUBDEL2, Type::NS, *SUBDEL_NS_RDATA);
        assert_eq!(zone.validate().unwrap(), []);

        // Wide glue policy when the nameserver is within a different
        // child zone: there should still be an error.
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Wide);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL, Type::NS, *APEX_NS_RDATA);
        add_rr(&mut zone, &SUBDEL2, Type::NS, *SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            [ValidationIssue::MissingGlue(NS_SUBDEL.clone())]
        );
    }

    #[test]
    fn validate_detects_missing_apex_ns() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, *APEX_SOA_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingApexNs]
        );
    }

    #[test]
    fn validate_detects_multiple_cname() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
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
            vec![ValidationIssue::DuplicateCname(&HOST1)]
        );
    }

    #[test]
    fn validate_detects_other_records_at_cname() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(
            &mut zone,
            &HOST1,
            Type::CNAME,
            HOST2.wire_repr().try_into().unwrap(),
        );
        add_rr(&mut zone, &HOST1, Type::A, *LOCALHOST_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::OtherRecordsAtCname(&HOST1)]
        );
    }

    #[test]
    fn validate_detects_missing_ns_address() {
        // First case: the apex NS record is missing an address.
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_rr(&mut zone, &APEX, Type::SOA, *APEX_SOA_RDATA);
        add_rr(&mut zone, &APEX, Type::NS, *APEX_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingNsAddress(NS.clone())]
        );

        // Second case: a delegation NS record which points to a name
        // within the zone is missing an address.
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &SUBDEL2, Type::NS, *SUBDEL_NS_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingNsAddress(NS_SUBDEL.clone())]
        );
    }

    #[test]
    fn validate_detects_missing_mx_address() {
        let mut zone = Zone::new(APEX.clone(), Class::IN, GluePolicy::Narrow);
        add_basic_rrs(&mut zone);
        add_rr(&mut zone, &APEX, Type::MX, *APEX_MX_RDATA);
        assert_eq!(
            zone.validate().unwrap(),
            vec![ValidationIssue::MissingMxAddress(MX.clone())]
        );
    }
}
