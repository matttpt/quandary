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

//! The [`HashMapTreeZone`] structure.

use std::borrow::Cow;

use crate::class::Class;
use crate::name::{Label, Name};
use crate::rr::{Rdata, Ttl, Type};

use super::super::rrset::RrsetList;
use super::super::zone::{
    Addresses, Cname, Found, GluePolicy, IteratedRrset, IteratorByNode, IteratorByRrset,
    LookupAddrsResult, LookupAllResult, LookupOptions, LookupResult, NoRecords, Referral,
    SingleRrset,
};
use super::super::{Error, Zone};

////////////////////////////////////////////////////////////////////////
// STRUCTURE AND BASIC OPERATIONS                                     //
////////////////////////////////////////////////////////////////////////

/// An in-memory [`Zone`] data structure that mirrors the DNS's tree
/// structure and stores the children of each node in a [`HashMap`].
///
/// A `HashMapTreeZone` stores the contents of a DNS zone in memory. It
/// offers good performance, and moreover it is easy to understand.
/// Since it replicates the DNS's tree structure, its implementation
/// follows the [RFC 1034 § 4.3.2] reference lookup algorithm closely,
/// and the source code is therefore a good place to go to understand
/// how DNS lookups work.
///
/// However, since the `HashMapTreeZone` uses hash maps internally, it
/// cannot support DNSSEC operations (which require ordered access).
///
/// [`HashMap`]: std::collections::HashMap
/// [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
#[derive(Clone, Debug)]
pub struct HashMapTreeZone {
    class: Class,
    glue_policy: GluePolicy,
    apex: Node,
}

type Node = super::node::Node<NodeData>;

#[derive(Clone, Debug, Default)]
struct NodeData {
    rrsets: RrsetList,
}

impl HashMapTreeZone {
    /// Creates a new `HashMapTreeZone` with the specified name, class,
    /// and glue policy. The zone is initially empty.
    pub fn new(name: Box<Name>, class: Class, glue_policy: GluePolicy) -> Self {
        Self {
            class,
            glue_policy,
            apex: Node::new(name),
        }
    }

    /// Adds a record to the `HashMapTreeZone`.
    ///
    /// This is designed with the "zone file" paradigm in mind: records
    /// are added in a "flat" manner, one by one. The implementation
    /// then takes care of maintaining consistency (see the failure
    /// conditions below) and organizing records into RRsets, which are
    /// then attached to `Node`s mirroring the conceptual DNS tree.
    ///
    /// This will fail if the provided owner is not within the zone, if
    /// the record's class does not match the zone, or if the record's
    /// TTL does not match other records in its RRset.
    ///
    /// **Warning:** this is currently *not* guaranteed to be an atomic
    /// operation, as it is expected that caller will abort the zone
    /// load if an error occurs. This will need to change to support
    /// dynamic updates (RFC 2136), but for now, *do not* continue to
    /// use the `HashMapTreeZone` if this fails: it may be in an
    /// inconsistent state.
    pub fn add(
        &mut self,
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<(), Error> {
        // NOTE: RrsetList::add will perform the TTL check.
        if !owner.eq_or_subdomain_of(self.name()) {
            Err(Error::NotInZone)
        } else if class != self.class {
            Err(Error::ClassMismatch)
        } else {
            let node = self
                .apex
                .get_or_create_descendant(owner, owner.len() - self.name().len());
            node.data.rrsets.add(rr_type, ttl, rdata)
        }
    }
}

////////////////////////////////////////////////////////////////////////
// ZONE IMPLEMENTATION                                                //
////////////////////////////////////////////////////////////////////////

impl Zone for HashMapTreeZone {
    fn name(&self) -> &Name {
        &self.apex.name
    }

    fn class(&self) -> Class {
        self.class
    }

    fn glue_policy(&self) -> GluePolicy {
        self.glue_policy
    }

    fn lookup(&self, name: &Name, rr_type: Type, options: LookupOptions) -> LookupResult {
        match self.lookup_base(name, options) {
            LookupBaseResult::Found {
                data,
                source_of_synthesis,
            } => {
                let source_of_synthesis = source_of_synthesis.map(Cow::Borrowed);
                if let Some(rrset) = data.rrsets.lookup(rr_type) {
                    LookupResult::Found(Found {
                        data: rrset.into(),
                        source_of_synthesis,
                    })
                } else if let Some(rrset) = data.rrsets.lookup(Type::CNAME) {
                    LookupResult::Cname(Cname {
                        rrset: rrset.into(),
                        source_of_synthesis,
                    })
                } else {
                    LookupResult::NoRecords(NoRecords {
                        source_of_synthesis,
                    })
                }
            }
            LookupBaseResult::Referral(r) => LookupResult::Referral(r),
            LookupBaseResult::NxDomain => LookupResult::NxDomain,
            LookupBaseResult::WrongZone => LookupResult::WrongZone,
        }
    }

    fn lookup_addrs(&self, name: &Name, options: LookupOptions) -> LookupAddrsResult {
        match self.lookup_base(name, options) {
            LookupBaseResult::Found {
                data,
                source_of_synthesis,
            } => {
                let a_rrset = data.rrsets.lookup(Type::A).map(SingleRrset::from);
                let aaaa_rrset = if self.class == Class::IN {
                    data.rrsets.lookup(Type::AAAA).map(SingleRrset::from)
                } else {
                    None
                };
                LookupAddrsResult::Found(Found {
                    data: Addresses {
                        a_rrset,
                        aaaa_rrset,
                    },
                    source_of_synthesis: source_of_synthesis.map(Cow::Borrowed),
                })
            }
            LookupBaseResult::Referral(r) => LookupAddrsResult::Referral(r),
            LookupBaseResult::NxDomain => LookupAddrsResult::NxDomain,
            LookupBaseResult::WrongZone => LookupAddrsResult::WrongZone,
        }
    }

    fn lookup_all(&self, name: &Name, options: LookupOptions) -> LookupAllResult {
        match self.lookup_base(name, options) {
            LookupBaseResult::Found {
                data,
                source_of_synthesis,
            } => LookupAllResult::Found(Found {
                data: Box::new(data.rrsets.iter().map(IteratedRrset::from)),
                source_of_synthesis: source_of_synthesis.map(Cow::Borrowed),
            }),
            LookupBaseResult::Referral(r) => LookupAllResult::Referral(r),
            LookupBaseResult::NxDomain => LookupAllResult::NxDomain,
            LookupBaseResult::WrongZone => LookupAllResult::WrongZone,
        }
    }

    fn soa(&self) -> Option<SingleRrset> {
        self.apex
            .data
            .rrsets
            .lookup(Type::SOA)
            .map(SingleRrset::from)
    }

    fn ns(&self) -> Option<SingleRrset> {
        self.apex
            .data
            .rrsets
            .lookup(Type::NS)
            .map(SingleRrset::from)
    }

    fn iter_by_node(&self) -> IteratorByNode {
        Box::new(self.apex.iter().map(|(name, data)| {
            let iter: Box<dyn Iterator<Item = IteratedRrset>> =
                Box::new(data.rrsets.iter().map(IteratedRrset::from));
            (name, iter)
        }))
    }

    fn iter_by_rrset(&self) -> IteratorByRrset {
        Box::new(
            self.apex
                .iter()
                .flat_map(|(name, data)| data.rrsets.iter().map(move |rrset| (name, rrset.into()))),
        )
    }
}

////////////////////////////////////////////////////////////////////////
// BASE LOOKUP IMPLEMENTATION                                         //
////////////////////////////////////////////////////////////////////////

enum LookupBaseResult<'a> {
    Found {
        data: &'a NodeData,
        source_of_synthesis: Option<&'a Name>,
    },
    Referral(Referral<'a>),
    NxDomain,
    WrongZone,
}

impl HashMapTreeZone {
    fn lookup_base(&self, name: &Name, options: LookupOptions) -> LookupBaseResult {
        if !options.unchecked && !name.eq_or_subdomain_of(&self.apex.name) {
            LookupBaseResult::WrongZone
        } else {
            let level = name.len() - self.name().len();
            lookup_impl(&self.apex, name, level, options.search_below_cuts, true)
        }
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
    search_below_cuts: bool,
    at_apex: bool,
) -> LookupBaseResult<'a> {
    // If the node has an NS record, that triggers a referral—even when
    // the node is the target node!
    if !at_apex && !search_below_cuts {
        if let Some(ns_rrset) = node.data.rrsets.lookup(Type::NS) {
            return LookupBaseResult::Referral(Referral {
                child_zone: Cow::Borrowed(&node.name),
                ns_rrset: ns_rrset.into(),
            });
        }
    }

    if level == 0 {
        LookupBaseResult::Found {
            data: &node.data,
            source_of_synthesis: None,
        }
    } else {
        // Try to traverse down the tree. If deeper nodes do not exist,
        // then this node is the "closest encloser" (see RFC 4592 §
        // 3.3.1), and we search for a wildcard domain name to be the
        // "source of synthesis" for the response.
        if let Some(subnode) = node.children.get(&name[level - 1]) {
            lookup_impl(subnode, name, level - 1, search_below_cuts, false)
        } else if let Some(source_of_synthesis) = node.children.get(Label::asterisk()) {
            LookupBaseResult::Found {
                data: &source_of_synthesis.data,
                source_of_synthesis: Some(&source_of_synthesis.name),
            }
        } else {
            LookupBaseResult::NxDomain
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::*;
    use crate::name::Label;

    lazy_static! {
        static ref NAME: Box<Name> = "quandary.test.".parse().unwrap();
        static ref OUTSIDE: Box<Name> = "other.test.".parse().unwrap();
        static ref LOCALHOST: &'static Rdata = (&[127, 0, 0, 1]).try_into().unwrap();
        static ref LOCALHOST6: &'static Rdata = (&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .try_into()
            .unwrap();
    }

    fn new_zone() -> HashMapTreeZone {
        HashMapTreeZone::new(NAME.clone(), Class::IN, GluePolicy::Narrow)
    }

    #[test]
    fn add_rejects_mismatched_class() {
        let mut zone = new_zone();
        assert_eq!(
            zone.add(&NAME, Type::A, Class::CH, Ttl::from(3600), &LOCALHOST),
            Err(Error::ClassMismatch),
        );
    }

    #[test]
    fn add_rejects_mismatched_ttl() {
        let mut zone = new_zone();
        zone.add(&NAME, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();
        assert_eq!(
            zone.add(&NAME, Type::A, Class::IN, Ttl::from(7200), &LOCALHOST),
            Err(Error::TtlMismatch),
        );
    }

    #[test]
    fn add_rejects_owner_outside_of_zone() {
        let mut zone = new_zone();
        assert_eq!(
            zone.add(&OUTSIDE, Type::A, Class::CH, Ttl::from(3600), &LOCALHOST),
            Err(Error::NotInZone),
        );
    }

    #[test]
    fn add_works() {
        // This test is designed to exercise both Zone::add and the
        // underlying Node::get_or_create_descendant method.

        let name: Box<Name> = "a.b.c.d.".parse().unwrap();
        let apex: Box<Name> = "d.".parse().unwrap();
        let mut zone = HashMapTreeZone::new(apex, Class::IN, GluePolicy::Narrow);
        zone.add(&name, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();

        // Verify that Zone::add had the expected results.
        let c_node = zone.apex.children.get(<&Label>::from(b"c")).unwrap();
        let b_node = c_node.children.get(<&Label>::from(b"b")).unwrap();
        let a_node = b_node.children.get(<&Label>::from(b"a")).unwrap();
        assert_eq!(a_node.children.len(), 0);
        assert_eq!(a_node.data.rrsets.iter().next().unwrap().rr_type, Type::A);

        // Finally, make sure that Node::get_or_create_descendant now
        // finds existing nodes, rather than creating new ones.
        let lookup_result = zone.apex.get_or_create_descendant(&name, 3);
        assert_eq!(
            lookup_result.data.rrsets.iter().next().unwrap().rr_type,
            Type::A,
        );
    }

    ////////////////////////////////////////////////////////////////////
    // LOOKUP TESTS                                                   //
    ////////////////////////////////////////////////////////////////////

    /// A shorthand to create a Box<Name>, panicking on errors.
    fn boxed_name(from: &str) -> Box<Name> {
        from.parse().unwrap()
    }

    /// Checks that an RRset has the expected RDATAs. The RDATAs are
    /// checked in order, which is really too strict. But since this
    /// implementation stores RDATAs in the order they were written,
    /// this works for these tests, because we know the order the RDATAs
    /// were added!
    fn check_rrset(rrset: &SingleRrset, expected_rdatas: &[&[u8]]) {
        let mut rdatas = rrset.rdatas.iter();
        for &expected_rdata in expected_rdatas {
            assert_eq!(rdatas.next().unwrap().octets(), expected_rdata);
        }
        assert!(rdatas.next().is_none());
    }

    #[test]
    fn lookup_works() {
        let mut zone = new_zone();
        let www = boxed_name("www.quandary.test.");
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();
        match zone.lookup(&www, Type::A, LookupOptions::default()) {
            LookupResult::Found(found) => {
                check_rrset(&found.data, &[LOCALHOST.octets()]);
                assert!(found.source_of_synthesis.is_none());
            }
            _ => panic!("expected an A record"),
        }
    }

    #[test]
    fn lookup_addrs_works() {
        let mut zone = new_zone();
        let www = boxed_name("www.quandary.test.");
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();
        match zone.lookup_addrs(&www, LookupOptions::default()) {
            LookupAddrsResult::Found(found) => {
                check_rrset(&found.data.a_rrset.unwrap(), &[LOCALHOST.octets()]);
                assert!(&found.data.aaaa_rrset.is_none());
                assert!(found.source_of_synthesis.is_none());
            }
            _ => panic!("expected addresses to be found"),
        }
        zone.add(&www, Type::AAAA, Class::IN, Ttl::from(3600), &LOCALHOST6)
            .unwrap();
        match zone.lookup_addrs(&www, LookupOptions::default()) {
            LookupAddrsResult::Found(found) => {
                check_rrset(&found.data.a_rrset.unwrap(), &[LOCALHOST.octets()]);
                check_rrset(&found.data.aaaa_rrset.unwrap(), &[LOCALHOST6.octets()]);
                assert!(found.source_of_synthesis.is_none());
            }
            _ => panic!("expected addresses to be found"),
        }
    }

    #[test]
    fn lookup_all_works() {
        let mut zone = new_zone();
        let www = boxed_name("www.quandary.test.");
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();
        zone.add(&www, Type::AAAA, Class::IN, Ttl::from(3600), &LOCALHOST6)
            .unwrap();
        match zone.lookup_all(&www, LookupOptions::default()) {
            LookupAllResult::Found(found) => {
                let rrsets: Vec<_> = found.data.collect();
                assert_eq!(rrsets.len(), 2);
                let mut seen_ipv4 = false;
                let mut seen_ipv6 = false;
                for rrset in rrsets {
                    let rr_type = rrset.rr_type;
                    let single_rrset = rrset.into();
                    match rr_type {
                        Type::A => {
                            check_rrset(&single_rrset, &[LOCALHOST.octets()]);
                            seen_ipv4 = true;
                        }
                        Type::AAAA => {
                            check_rrset(&single_rrset, &[LOCALHOST6.octets()]);
                            seen_ipv6 = true;
                        }
                        _ => panic!("unexpected RRset returned"),
                    }
                }
                assert!(seen_ipv4);
                assert!(seen_ipv6);
                assert!(found.source_of_synthesis.is_none());
            }
            _ => panic!("expected to find a node"),
        };
    }

    #[test]
    fn lookups_handle_nxdomain() {
        let zone = new_zone();
        let www = boxed_name("www.quandary.test.");
        assert!(matches!(
            zone.lookup(&www, Type::A, LookupOptions::default()),
            LookupResult::NxDomain,
        ));
        assert!(matches!(
            zone.lookup_addrs(&www, LookupOptions::default()),
            LookupAddrsResult::NxDomain,
        ));
        assert!(matches!(
            zone.lookup_all(&www, LookupOptions::default()),
            LookupAllResult::NxDomain,
        ));
    }

    #[test]
    fn lookup_handles_exists_but_no_records() {
        let mut zone = new_zone();
        let www = boxed_name("www.quandary.test.");
        zone.add(&www, Type::A, Class::IN, Ttl::from(3600), &LOCALHOST)
            .unwrap();
        assert!(matches!(
            zone.lookup(&www, Type::AAAA, LookupOptions::default()),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
    }

    #[test]
    fn lookups_reject_wrong_zone() {
        let zone = new_zone();
        assert!(matches!(
            zone.lookup(&OUTSIDE, Type::A, LookupOptions::default()),
            LookupResult::WrongZone,
        ));
        assert!(matches!(
            zone.lookup_addrs(&OUTSIDE, LookupOptions::default()),
            LookupAddrsResult::WrongZone,
        ));
        assert!(matches!(
            zone.lookup_all(&OUTSIDE, LookupOptions::default()),
            LookupAllResult::WrongZone,
        ));
    }

    #[test]
    fn referral_processing_works() {
        let mut zone = new_zone();
        let subdel = boxed_name("subdel.quandary.test.");
        let ns = boxed_name("ns.subdel.quandary.test.");
        let ns_rdata = ns.wire_repr().try_into().unwrap();
        let addr_rdata = b"\x7f\x00\x00\x01".try_into().unwrap();
        zone.add(&subdel, Type::NS, Class::IN, Ttl::from(3600), ns_rdata)
            .unwrap();
        zone.add(&ns, Type::A, Class::IN, Ttl::from(3600), addr_rdata)
            .unwrap();

        // With search_below_cuts == false, we expect a referral, even
        // when the target name is the delegation point.
        for name in [&ns, &subdel] {
            match zone.lookup_all(name, LookupOptions::default()) {
                LookupAllResult::Referral(referral) => {
                    assert_eq!(referral.child_zone.as_ref(), subdel.as_ref());
                    check_rrset(&referral.ns_rrset, &[ns_rdata.octets()]);
                }
                _ => panic!("expected a referral"),
            }
        }

        // With search_below_cuts == true, we expect lookups to enter
        // non-authoritative data.
        let lookup_options = LookupOptions {
            unchecked: false,
            search_below_cuts: true,
        };
        match zone.lookup(&ns, Type::A, lookup_options) {
            LookupResult::Found(found) => check_rrset(&found.data, &[addr_rdata.octets()]),
            _ => panic!("expected a single A record"),
        }
    }

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
        let mut zone = HashMapTreeZone::new(apex, Class::IN, GluePolicy::Narrow);
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
        match zone.lookup(
            &boxed_name("host3.example."),
            Type::MX,
            LookupOptions::default(),
        ) {
            LookupResult::Found(found) => {
                check_rrset(&found.data, &[RFC_4592_MX]);
                assert_eq!(
                    found.source_of_synthesis,
                    Some(Cow::Owned(boxed_name("*.example."))),
                );
            }
            _ => panic!("host3.example. MX did not return the expected record"),
        }
        assert!(matches!(
            zone.lookup(
                &boxed_name("host3.example."),
                Type::A,
                LookupOptions::default(),
            ),
            LookupResult::NoRecords(no_records)
                if no_records.source_of_synthesis == Some(Cow::Owned(boxed_name("*.example."))),
        ));
        match zone.lookup(
            &boxed_name("foo.bar.example."),
            Type::TXT,
            LookupOptions::default(),
        ) {
            LookupResult::Found(found) => {
                check_rrset(&found.data, &[RFC_4592_WILDCARD_TXT]);
                assert_eq!(
                    found.source_of_synthesis,
                    Some(Cow::Owned(boxed_name("*.example."))),
                );
            }
            _ => panic!("foo.bar.example. TXT did not return the expected record"),
        }

        // The following do not trigger wildcard synthesis. (See RFC
        // 4592 § 2.2.1 for the reasons why!)
        assert!(matches!(
            zone.lookup(&boxed_name("host1.example."), Type::MX, LookupOptions::default()),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
        assert!(matches!(
            zone.lookup(&boxed_name("sub.*.example."), Type::MX, LookupOptions::default()),
            LookupResult::NoRecords(no_records) if no_records.source_of_synthesis.is_none(),
        ));
        assert!(matches!(
            zone.lookup(
                &boxed_name("_telnet._tcp.host1.example."),
                Type::SRV,
                LookupOptions::default(),
            ),
            LookupResult::NxDomain
        ));
        match zone.lookup(
            &boxed_name("host.subdel.example."),
            Type::A,
            LookupOptions::default(),
        ) {
            LookupResult::Referral(referral) => {
                assert_eq!(
                    referral.child_zone.as_ref(),
                    boxed_name("subdel.example.").as_ref(),
                );
                check_rrset(&referral.ns_rrset, &[RFC_4592_NS1, RFC_4592_NS2]);
            }
            _ => panic!("host.subdel.example. A did not return the expected referral"),
        }
        assert!(matches!(
            zone.lookup(
                &boxed_name("ghost.*.example."),
                Type::MX,
                LookupOptions::default(),
            ),
            LookupResult::NxDomain,
        ));
    }
}
