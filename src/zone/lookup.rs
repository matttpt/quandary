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

//! Implementation of step 3 of the lookup process for nameservers, as
//! described in [RFC 1034 § 4.3.2] and clarified by [RFC 4592].
//!
//! In step 2, the zone that should be searched (i.e., the one that is
//! the nearest ancestor to QNAME) was identified. Now, we search that
//! zone's database for the node corresponding to QNAME, or if this
//! fails, corresponding to an appropriate wildcard domain name. If and
//! when an appropriate node is found, it is searched for records
//! matching the QTYPE.
//!
//! Calling code must complete step 2, and convert QTYPE into the proper
//! TYPE(s) to search. Then, it may use [`Zone::lookup`] to search for
//! records for QNAME of a given TYPE within the target zone, or
//! [`Zone::lookup_all`] to search for *all* records for QNAME (e.g. to
//! handle queries with QTYPE `*`). These return a [`LookupResult`] and
//! [`LookupAllResult`], respectively.
//!
//! The aforementioned methods process referrals: they may return a
//! value of [`LookupResult::Referral`] or
//! [`LookupAllResult::Referral`], which indicates that QNAME is below a
//! zone cut (and provides the name of the delegated zone and the NS
//! RRset needed to respond to the query). This is generally the desired
//! behavior, but the underlying implementations [`Zone::lookup_raw`]
//! and [`Zone::lookup_all_raw`] provide a knob (the `process_referrals`
//! parameter) to turn this off. When `process_referrals` is `false`,
//! the search will continue *below* a zone cut, out of authoritative
//! data. This behavior is primarily intended to look up glue records.
//!
//! The core implementation of the lookup algorithm is the private
//! `lookup_impl` function in this module.
//!
//! [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
//! [RFC 4592]: https://datatracker.ietf.org/doc/html/rfc4592

use crate::name::{Label, Name};
use crate::rr::{Rrset, RrsetList, Type};

use super::{Node, Zone};

/// The result of a lookup of records of a specific type.
#[derive(Debug)]
pub enum LookupResult<'a> {
    /// The desired records were found.
    Found(Found<'a>),

    /// No records were found, but a CNAME record was present.
    Cname(Cname<'a>),

    /// The lookup encountered an NS RRset and would therefore leave
    /// authoritative data.
    Referral(Referral<'a>),

    /// A node with the given name exists, but it has no records of the
    /// desired type.
    NoRecords(NoRecords<'a>),

    /// No node with the given name exists.
    NxDomain,

    /// The provided name is not within the zone's hierarchy.
    WrongZone,
}

/// The result of a lookup of *all* records for a name.
#[derive(Debug)]
pub enum LookupAllResult<'a> {
    /// A node with the given name exists.
    Found(FoundAll<'a>),

    /// The lookup encountered an NS RRset and would therefore leave
    /// authoritative data.
    Referral(Referral<'a>),

    /// No node with the given name exists.
    NxDomain,

    /// The provided name is not within the zone's hierarchy.
    WrongZone,
}

/// Data returned when a single-type lookup finds records of the
/// requested type.
#[derive(Debug)]
pub struct Found<'a> {
    /// The RRset that was looked up.
    pub rrset: &'a Rrset,

    /// If this result was synthesized from a wildcard domain name, this
    /// indicates the source of synthesis.
    pub source_of_synthesis: Option<&'a Name>,
}

/// Data returned when a lookup of all record types successfully finds
/// the target domain name.
#[derive(Debug)]
pub struct FoundAll<'a> {
    /// The RRsets of the domain name that was looked up.
    pub rrsets: &'a RrsetList,

    /// If this result was synthesized from a wildcard domain name, this
    /// indicates the source of synthesis.
    pub source_of_synthesis: Option<&'a Name>,
}

/// Data returned when a single-type lookup finds a CNAME at the target
/// domain (and another RR type was requested).
#[derive(Debug)]
pub struct Cname<'a> {
    /// The CNAME RRset found at the target domain name.
    pub rrset: &'a Rrset,

    /// If this result was synthesized from a wildcard domain name, this
    /// indicates the source of synthesis.
    pub source_of_synthesis: Option<&'a Name>,
}

/// Data returned when a lookup encounters a zone cut.
#[derive(Debug)]
pub struct Referral<'a> {
    /// The domain name of the child zone, i.e., the name at which NS
    /// records were found.
    pub child_zone: &'a Name,

    /// The NS RRset found at the zone cut.
    pub ns_rrset: &'a Rrset,
}

/// Data returned when a single-type lookup finds the target domain
/// name, but it owns no records of the requested RR type.
#[derive(Debug)]
pub struct NoRecords<'a> {
    /// If this result was synthesized from a wildcard domain name, this
    /// indicates the source of synthesis.
    pub source_of_synthesis: Option<&'a Name>,
}

impl Zone {
    /// Looks up records for the given name and RR type, with referral
    /// processing.
    ///
    /// If the lookup process reaches a node with an NS record (and
    /// would therefore leave authoritative data),
    /// [`LookupResult::Referral`] is returned with the name of the
    /// node and its NS [`Rrset`].
    pub fn lookup(&self, name: &Name, rr_type: Type) -> LookupResult {
        self.lookup_raw(name, rr_type, true)
    }

    /// Looks up *all* records for the given name, with referral
    /// processing.
    ///
    /// If the lookup process reaches a node with an NS record (and
    /// would therefore leave authoritative data),
    /// [`LookupAllResult::Referral`] is returned with the name of the
    /// node and its NS [`Rrset`].
    pub fn lookup_all(&self, name: &Name) -> LookupAllResult {
        self.lookup_all_raw(name, true)
    }

    /// Looks up records for the given name and RR type, *optionally*
    /// processing referrals.
    ///
    /// If `process_referrals` is `false`, the lookup process will
    /// continue below zone cuts into non-authoritative data.
    /// Consequently, [`LookupResult::Referral`] will never be returned.
    /// This is primarily useful for looking up glue records.
    pub fn lookup_raw(&self, name: &Name, rr_type: Type, process_referrals: bool) -> LookupResult {
        match self.lookup_all_raw(name, process_referrals) {
            LookupAllResult::Found(found_all) => {
                if let Some(rrset) = found_all.rrsets.lookup(rr_type) {
                    LookupResult::Found(Found {
                        rrset,
                        source_of_synthesis: found_all.source_of_synthesis,
                    })
                } else if let Some(rrset) = found_all.rrsets.lookup(Type::CNAME) {
                    LookupResult::Cname(Cname {
                        rrset,
                        source_of_synthesis: found_all.source_of_synthesis,
                    })
                } else {
                    LookupResult::NoRecords(NoRecords {
                        source_of_synthesis: found_all.source_of_synthesis,
                    })
                }
            }
            LookupAllResult::Referral(referral) => LookupResult::Referral(referral),
            LookupAllResult::NxDomain => LookupResult::NxDomain,
            LookupAllResult::WrongZone => LookupResult::WrongZone,
        }
    }

    /// Looks up *all* records for the given name and RR type,
    /// *optionally* processing referrals.
    ///
    /// If `process_referrals` is `false`, the lookup process will
    /// continue below zone cuts into non-authoritative data.
    /// Consequently, [`LookupAllResult::Referral`] will never be
    /// returned. This is primarily useful for looking up glue records.
    pub fn lookup_all_raw(&self, name: &Name, process_referrals: bool) -> LookupAllResult {
        if !name.eq_or_subdomain_of(self.name()) {
            LookupAllResult::WrongZone
        } else {
            let level = name.len() - self.name().len();
            lookup_impl(&self.apex, name, level, process_referrals, true)
        }
    }

    /// Looks up the SOA record at the zone's apex (for convenience and
    /// performance).
    pub fn soa(&self) -> Option<&Rrset> {
        self.apex.rrsets.lookup(Type::SOA)
    }

    /// Looks up the NS record at the zone's apex (for convenience and
    /// performance).
    pub fn ns(&self) -> Option<&Rrset> {
        self.apex.rrsets.lookup(Type::NS)
    }
}

/// Implements the DNS lookup algorithm.
///
/// `node` is the deepest node we have matched so far; this node
/// corresponds to the label `name[level]`. If we have not reached the
/// target node, the function attempts to recursively match down the
/// tree. When `process_referrals` is `true`, a non-apex node with an NS
/// record will result in a referral; otherwise, the search will
/// continue into non-authoritative data. We need to keep track of whether
/// we're at the zone apex, so the first call should set `at_apex` to
/// `true`.
fn lookup_impl<'a>(
    node: &'a Node,
    name: &Name,
    level: usize,
    process_referrals: bool,
    at_apex: bool,
) -> LookupAllResult<'a> {
    // If the node has an NS record, that triggers a referral—even when
    // the node is the target node!
    if !at_apex && process_referrals {
        if let Some(ns_rrset) = node.rrsets.lookup(Type::NS) {
            return LookupAllResult::Referral(Referral {
                child_zone: &node.name,
                ns_rrset,
            });
        }
    }

    if level == 0 {
        LookupAllResult::Found(FoundAll {
            rrsets: &node.rrsets,
            source_of_synthesis: None,
        })
    } else {
        // Try to traverse down the tree. If deeper nodes do not exist,
        // then this node is the "closest encloser" (see RFC 4592 §
        // 3.3.1), and we search for a wildcard domain name to be the
        // "source of synthesis" for the response.
        if let Some(subnode) = node.children.get(&name[level - 1]) {
            lookup_impl(subnode, name, level - 1, process_referrals, false)
        } else if let Some(source_of_synthesis) = node.children.get(Label::asterisk()) {
            LookupAllResult::Found(FoundAll {
                rrsets: &source_of_synthesis.rrsets,
                source_of_synthesis: Some(&source_of_synthesis.name),
            })
        } else {
            LookupAllResult::NxDomain
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::super::{GluePolicy, Zone};
    use super::{LookupAllResult, LookupResult};
    use crate::class::Class;
    use crate::name::Name;
    use crate::rr::{Rrset, Ttl, Type};

    /// A shorthand to create a Box<Name>, panicking on errors.
    fn boxed_name(from: &str) -> Box<Name> {
        from.parse().unwrap()
    }

    /// Checks that an RRset has the expected type and RDATAs. The
    /// RDATAs are checked in order, which is really too strict. But
    /// since our RR handling code stores RDATAs in the order they were
    /// written, this works for these tests, because we know the order
    /// the RDATAs were added!
    fn check_rrset(rrset: &Rrset, expected_type: Type, expected_rdatas: &[&[u8]]) {
        assert_eq!(rrset.rr_type, expected_type);
        let mut rdatas = rrset.rdatas();
        for &expected_rdata in expected_rdatas {
            assert_eq!(rdatas.next().unwrap().octets(), expected_rdata);
        }
        assert!(rdatas.next().is_none());
    }

    ////////////////////////////////////////////////////////////////////
    // BASIC TESTS                                                    //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn lookup_works() {
        let mut zone = Zone::new(boxed_name("quandary.test."), Class::IN, GluePolicy::Narrow);
        let www = boxed_name("www.quandary.test.");
        let localhost = b"\x7f\x00\x00\x01".try_into().unwrap();
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), localhost)
            .unwrap();
        match zone.lookup(&www, Type::A) {
            LookupResult::Found(found) => {
                check_rrset(found.rrset, Type::A, &[localhost.octets()]);
                assert!(found.source_of_synthesis.is_none());
            }
            _ => panic!("expected an A record"),
        }
    }

    #[test]
    fn lookup_handles_nxdomain() {
        let zone = Zone::new(boxed_name("quandary.test."), Class::IN, GluePolicy::Narrow);
        let www = boxed_name("www.quandary.test.");
        assert!(matches!(zone.lookup(&www, Type::A), LookupResult::NxDomain));
    }

    #[test]
    fn lookup_handles_exists_but_no_records() {
        let mut zone = Zone::new(boxed_name("quandary.test."), Class::IN, GluePolicy::Narrow);
        let www = boxed_name("www.quandary.test.");
        let localhost = b"\x7f\x00\x00\x01".try_into().unwrap();
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), localhost)
            .unwrap();
        assert!(matches!(
            zone.lookup(&www, Type::AAAA),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
    }

    #[test]
    fn lookup_all_raw_rejects_wrong_zone() {
        // ... and if it does, its various wrappers should too!
        let zone = Zone::new(boxed_name("quandary.test."), Class::IN, GluePolicy::Narrow);
        let other: Box<Name> = "other.test.".parse().unwrap();
        assert!(matches!(
            zone.lookup_all_raw(&other, false),
            LookupAllResult::WrongZone
        ));
    }

    #[test]
    fn referral_processing_works() {
        let mut zone = Zone::new(boxed_name("quandary.test."), Class::IN, GluePolicy::Narrow);
        let subdel = boxed_name("subdel.quandary.test.");
        let ns = boxed_name("ns.subdel.quandary.test.");
        let ns_rdata = ns.wire_repr().try_into().unwrap();
        let addr_rdata = b"\x7f\x00\x00\x01".try_into().unwrap();
        zone.add(&subdel, Type::NS, Class::IN, Ttl::from(3600), ns_rdata)
            .unwrap();
        zone.add(&ns, Type::A, Class::IN, Ttl::from(3600), addr_rdata)
            .unwrap();

        // With process_referrals == true, we expect a referral, even
        // when the target name is the delegation point.
        for name in [&ns, &subdel] {
            match zone.lookup_all_raw(name, true) {
                LookupAllResult::Referral(referral) => {
                    assert_eq!(referral.child_zone, subdel.as_ref());
                    check_rrset(referral.ns_rrset, Type::NS, &[ns_rdata.octets()]);
                }
                _ => panic!("expected a referral"),
            }
        }

        // With process_referrals == false, we expect lookups to enter
        // non-authoritative data.
        match zone.lookup_raw(&ns, Type::A, false) {
            LookupResult::Found(found) => check_rrset(found.rrset, Type::A, &[addr_rdata.octets()]),
            _ => panic!("expected a single A record"),
        }
    }

    ////////////////////////////////////////////////////////////////////
    // RFC 4592                                                       //
    ////////////////////////////////////////////////////////////////////

    // RFC 4592 § 2.2.1 provides examples of wildcard synthesis. We
    // replicate the examples here, since (a) it verifies the
    // correctness of our wildcard processing, and (b) it's in general a
    // nice workout for the lookup code.

    // Data for the zone presented as an example in RFC 4592 § 2.2.1.
    // Some records have lengthy RDATA that does not matter for the
    // tests, so (following the RFC itself) there are omissions.
    static RFC_4592_MX: &[u8] = b"\x00\x0a\x05host1\x07example\x00";
    static RFC_4592_NS1: &[u8] = b"\x02ns\x07example\x03com\x00";
    static RFC_4592_NS2: &[u8] = b"\x02ns\x07example\x03net\x00";
    static RFC_4592_WILDCARD_TXT: &[u8] = b"\x12this is a wildcard";
    static RFC_4592_ZONE: &[(&str, Type, &[u8])] = &[
        ("example.", Type::SOA, b"<SOA RDATA>"),
        ("example.", Type::NS, RFC_4592_NS1),
        ("example.", Type::NS, RFC_4592_NS2),
        ("*.example.", Type::TXT, RFC_4592_WILDCARD_TXT),
        ("*.example.", Type::MX, RFC_4592_MX),
        ("sub.*.example.", Type::TXT, b"\x16this is not a wildcard"),
        ("host1.example.", Type::A, b"\xc0\x00\x02\x01"),
        ("_ssh._tcp.host1.example.", Type::SRV, b"<SRV DATA>"),
        ("_ssh._tcp.host2.example.", Type::SRV, b"<SRV DATA>"),
        ("subdel.example.", Type::NS, RFC_4592_NS1),
        ("subdel.example.", Type::NS, RFC_4592_NS2),
    ];

    #[test]
    fn rfc_4592_examples() {
        let apex: Box<Name> = "example.".parse().unwrap();
        let mut zone = Zone::new(apex, Class::IN, GluePolicy::Narrow);
        for &(owner_str, rr_type, rdata) in RFC_4592_ZONE {
            let owner: Box<Name> = owner_str.parse().unwrap();
            zone.add(
                &owner,
                rr_type,
                Class::IN,
                Ttl::from(3600),
                rdata.try_into().unwrap(),
            )
            .unwrap();
        }

        // The following are synthesized from a wildcard.
        match zone.lookup(&boxed_name("host3.example."), Type::MX) {
            LookupResult::Found(found) => {
                check_rrset(found.rrset, Type::MX, &[RFC_4592_MX]);
                assert_eq!(
                    found.source_of_synthesis,
                    Some(boxed_name("*.example.").as_ref()),
                );
            }
            _ => panic!("host3.example. MX did not return the expected record"),
        }
        assert!(matches!(
            zone.lookup(&boxed_name("host3.example."), Type::A),
            LookupResult::NoRecords(no_records)
                if no_records.source_of_synthesis == Some(boxed_name("*.example.").as_ref()),
        ));
        match zone.lookup(&boxed_name("foo.bar.example."), Type::TXT) {
            LookupResult::Found(found) => {
                check_rrset(found.rrset, Type::TXT, &[RFC_4592_WILDCARD_TXT]);
                assert_eq!(
                    found.source_of_synthesis,
                    Some(boxed_name("*.example.").as_ref()),
                );
            }
            _ => panic!("foo.bar.example. TXT did not return the expected record"),
        }

        // The following do not trigger wildcard synthesis. (See RFC
        // 4592 § 2.2.1 for the reasons why!)
        assert!(matches!(
            zone.lookup(&boxed_name("host1.example."), Type::MX),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
        assert!(matches!(
            zone.lookup(&boxed_name("sub.*.example."), Type::MX),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
        assert!(matches!(
            zone.lookup(&boxed_name("_telnet._tcp.host1.example."), Type::SRV),
            LookupResult::NxDomain
        ));
        match zone.lookup(&boxed_name("host.subdel.example."), Type::A) {
            LookupResult::Referral(referral) => {
                assert_eq!(referral.child_zone, boxed_name("subdel.example.").as_ref());
                check_rrset(referral.ns_rrset, Type::NS, &[RFC_4592_NS1, RFC_4592_NS2]);
            }
            _ => panic!("host.subdel.example. A did not return the expected referral"),
        }
        assert!(matches!(
            zone.lookup(&boxed_name("ghost.*.example."), Type::MX),
            LookupResult::NxDomain
        ));
    }
}
