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

//! Implementation of DNS zone data structures, for keeping DNS zones
//! loaded in memory.

use std::collections::HashMap;

use crate::class::Class;
use crate::name::{LabelBuf, Name};
use crate::rr::{Rdata, RrsetList, Ttl, Type};

mod error;
mod lookup;
mod validation;
pub use error::Error;
pub use lookup::{Cname, Found, FoundAll, LookupAllResult, LookupResult, NoRecords, Referral};
pub use validation::ValidationIssue;

/// A DNS zone loaded into memory.
///
/// The most important part of a `Zone` is its tree of `Node`s (a
/// private structure that represents a node in the DNS tree), which
/// own RRsets. [`Zone::lookup`] and related methods allow the zone's
/// data to be queried, according to the algorithm specified by
/// [RFC 1034 § 4.3.2]. The `lookup` module provides the implementation.
/// The zone's data can also be checked for semantic correctness; see
/// [`Zone::validate`] and the `validation` module, which provides the
/// implementation.
///
/// `Zone`s are constructed with [`Zone::new`], which provides an empty
/// structure, and subsequent calls to [`Zone::add`], which adds
/// resource records to the zone.
///
/// [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
#[derive(Debug)]
pub struct Zone {
    class: Class,
    glue_policy: GluePolicy,
    apex: Node,
}

/// A node in the DNS tree, which may own RRsets.
#[derive(Debug)]
struct Node {
    name: Box<Name>,
    rrsets: RrsetList,
    // TODO: Do we want to use LabelBuf here? Or should we use a boxed
    // Label? If so, LabelBuf can be removed from the software.
    children: HashMap<LabelBuf, Node>,
}

impl Zone {
    /// Creates a new `Zone` with the specified name, class, and glue
    /// policy. The zone is initially empty.
    pub fn new(name: Box<Name>, class: Class, glue_policy: GluePolicy) -> Self {
        Self {
            class,
            glue_policy,
            apex: Node {
                name,
                rrsets: RrsetList::new(),
                children: HashMap::new(),
            },
        }
    }

    // Returns the zone's name.
    pub fn name(&self) -> &Name {
        &self.apex.name
    }

    // Returns the zone's class.
    pub fn class(&self) -> Class {
        self.class
    }

    // Returns the zone's glue policy.
    pub fn glue_policy(&self) -> GluePolicy {
        self.glue_policy
    }

    /// Adds a record to the `Zone`.
    ///
    /// This is designed with the "zone file" paradigm in mind: records
    /// are added in a "flat" manner, one by one. The implementation
    /// then takes care of maintaining consistency (see the failure
    /// conditions below) and organizing records into RRsets, which are
    /// then attached to `Node`s mirroring the conceptual DNS tree.
    ///
    /// This will fail if the provided owner is not within the zone, if
    /// the record's class does not match the zone, or if the record's
    /// TTL does not match other records in its RRset. (These are
    /// checks 1, 10, and 11, described in the `validation` module.)
    ///
    /// **Warning:** this is currently *not* guaranteed to be an atomic
    /// operation, as it is expected that caller will abort the zone
    /// load if an error occurs. This will need to change to support
    /// dynamic updates (RFC 2136), but for now, *do not* continue to
    /// use the `Zone` if this fails: it may be in an inconsistent
    /// state.
    pub fn add(
        &mut self,
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<(), Error> {
        // NOTE: RrsetList::add will perform the TTL check. While it
        // will also check the CLASS against existing records in the
        // list, we need to check that that is this zone's CLASS.
        if !owner.eq_or_subdomain_of(self.name()) {
            return Err(Error::NotInZone);
        }
        if class != self.class {
            return Err(Error::ClassMismatch);
        }
        let node = self
            .apex
            .get_or_create_descendant(owner, owner.len() - self.apex.name.len());
        node.rrsets
            .add(rr_type, class, ttl, rdata)
            .map_err(|e| e.into())
    }
}

impl Node {
    /// Gets or creates a descendant node corresponding to `name`. Any
    /// nodes between the target descendant node and `self` will also be
    /// created. `level` should be set so that `self` corresponds to the
    /// label `name[level]`.
    fn get_or_create_descendant(&mut self, name: &Name, level: usize) -> &mut Node {
        if level == 0 {
            self
        } else {
            self.children
                .entry(name[level - 1].to_owned())
                .or_insert_with(|| Node {
                    name: name.superdomain(level - 1).unwrap(),
                    rrsets: RrsetList::new(),
                    children: HashMap::new(),
                })
                .get_or_create_descendant(name, level - 1)
        }
    }
}

/// Glue-record policies for DNS zones.
///
/// In order to validate a zone, we ensure that glue records are present
/// for all NS records that require it. There are, however, different
/// ways of determining whether an NS record requires glue. Two common
/// policies for this are as follows:
///
/// 1. The "wide" glue policy: glue is required if and only if the
///    nameserver is in *any* zone below the parent zone.
/// 2. The "narrow" glue policy: glue is required if and only if the
///    nameserver is in the child zone (specified by the owner of the NS
///    record).
///
/// The "narrow" policy is suggested by [RFC 1034 § 4.2.1]. The "wide"
/// policy is used for the root zone. Both policies are described in the
/// [draft-koch-dns-glue-clarifications-05] Internet Draft.
///
/// This enumeration represents these glue policies.
///
/// [RFC 1034 § 4.2.1]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.2.1
/// [draft-koch-dns-glue-clarifications-05]: https://datatracker.ietf.org/doc/html/draft-koch-dns-glue-clarifications-05
#[derive(Clone, Copy, Debug)]
pub enum GluePolicy {
    Narrow,
    Wide,
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
    }

    fn new_zone() -> Zone {
        Zone::new(NAME.clone(), Class::IN, GluePolicy::Narrow)
    }

    #[test]
    fn add_rejects_mismatched_class() {
        let mut zone = new_zone();
        assert_eq!(
            zone.add(&NAME, Type::A, Class::CH, Ttl::from(3600), *LOCALHOST),
            Err(Error::ClassMismatch)
        );
    }

    #[test]
    fn add_rejects_mismatched_ttl() {
        let mut zone = new_zone();
        zone.add(&NAME, Type::A, Class::IN, Ttl::from(3600), *LOCALHOST)
            .unwrap();
        assert_eq!(
            zone.add(&NAME, Type::A, Class::IN, Ttl::from(7200), *LOCALHOST),
            Err(Error::TtlMismatch)
        );
    }

    #[test]
    fn add_rejects_owner_outside_of_zone() {
        let mut zone = new_zone();
        assert_eq!(
            zone.add(&OUTSIDE, Type::A, Class::CH, Ttl::from(3600), *LOCALHOST),
            Err(Error::NotInZone)
        );
    }

    #[test]
    fn add_works() {
        // This test is designed to exercise both Zone::add and the
        // underlying Node::get_or_create_descendant method.

        let name: Box<Name> = "a.b.c.d.".parse().unwrap();
        let apex: Box<Name> = "d.".parse().unwrap();
        let mut zone = Zone::new(apex, Class::IN, GluePolicy::Narrow);
        zone.add(&name, Type::A, Class::IN, Ttl::from(3600), *LOCALHOST)
            .unwrap();

        // Verify that Zone::add had the expected results.
        let c_node = zone.apex.children.get(<&Label>::from(b"c")).unwrap();
        let b_node = c_node.children.get(<&Label>::from(b"b")).unwrap();
        let a_node = b_node.children.get(<&Label>::from(b"a")).unwrap();
        assert_eq!(a_node.children.len(), 0);
        assert_eq!(a_node.rrsets.iter().next().unwrap().rr_type, Type::A);

        // Finally, make sure that Node::get_or_create_descendant now
        // finds existing nodes, rather than creating new ones.
        let lookup_result = zone.apex.get_or_create_descendant(&name, 3);
        assert_eq!(lookup_result.rrsets.iter().next().unwrap().rr_type, Type::A);
    }
}
