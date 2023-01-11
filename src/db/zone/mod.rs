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

//! The [`Zone`] trait and related types.

use std::borrow::Cow;
use std::fmt::Debug;

use crate::class::Class;
use crate::name::Name;
use crate::rr::{RdataSet, Ttl, Type};

use super::Error;

mod validation;

pub use validation::ValidationIssue;

////////////////////////////////////////////////////////////////////////
// ZONE TRAIT                                                         //
////////////////////////////////////////////////////////////////////////

/// Trait for zone data sources.
///
/// The `Zone` trait abstracts accesses to zone data. Its essential
/// operations are its three lookup methods: [`Zone::lookup`],
/// [`Zone::lookup_addrs`], and [`Zone::lookup_all`].
///
/// See the [`db` module documentation](crate::db#zones-and-catalogs)
/// for more information.
pub trait Zone {
    /// Returns the name of the zone (i.e., the domain name of the
    /// zone's apex node).
    fn name(&self) -> &Name;

    /// Returns the DNS class of the zone.
    fn class(&self) -> Class;

    /// Returns the zone's [`GluePolicy`].
    fn glue_policy(&self) -> GluePolicy;

    /// Looks up records of the given type at the provided domain name.
    fn lookup(&self, name: &Name, rr_type: Type, options: LookupOptions) -> LookupResult;

    /// Looks up all address records at the provided domain name.
    ///
    /// Implementations must return A records regardless of the zone's
    /// class, and must also include AAAA records when the zone is in
    /// the Internet (IN) class. As a best practice, when returning the
    /// [`LookupAddrsResult::Found`] variant, implementations should
    /// always set the [`Addresses::aaaa_rrset`] field to `None` when
    /// the class is not IN. Likewise, callers should only access
    /// the `aaaa_rrset` field when the class is IN.
    fn lookup_addrs(&self, name: &Name, options: LookupOptions) -> LookupAddrsResult;

    /// Looks up all records present at the provided domain name.
    fn lookup_all(&self, name: &Name, options: LookupOptions) -> LookupAllResult;

    /// Returns the SOA RRset at the zone's apex, if it exists.
    ///
    /// A default implementation that uses [`Zone::lookup`] is provided.
    /// `Zone` implementers may wish to provide a more efficient custom
    /// implementation if possible.
    fn soa(&self) -> Option<SingleRrset> {
        let lookup_options = LookupOptions {
            unchecked: true,
            search_below_cuts: false,
        };
        match self.lookup(self.name(), Type::SOA, lookup_options) {
            LookupResult::Found(found) => Some(found.data),
            _ => None,
        }
    }

    /// Returns the NS RRset at the zone's apex, if it exists.
    ///
    /// A default implementation that uses [`Zone::lookup`] is provided.
    /// `Zone` implementers may wish to provide a more efficient custom
    /// implementation if possible.
    fn ns(&self) -> Option<SingleRrset> {
        let lookup_options = LookupOptions {
            unchecked: true,
            search_below_cuts: false,
        };
        match self.lookup(self.name(), Type::NS, lookup_options) {
            LookupResult::Found(found) => Some(found.data),
            _ => None,
        }
    }

    /// Returns an iterator over the nodes of a zone. For each node, the
    /// node's domain name and iterator over its RRsets is produced.
    ///
    /// If grouping by node is not required, prefer to use
    /// [`Zone::iter_by_rrset`].
    fn iter_by_node(&self) -> IteratorByNode;

    /// Returns an iterator over the RRsets of the zone.
    ///
    /// For convenience, this method has a provided implementation
    /// that flattens the iterator returned by [`Zone::iter_by_node`].
    /// However, `Zone` implementers are encouraged to provide a custom
    /// implementation to eliminate unnecessary boxing.
    fn iter_by_rrset(&self) -> IteratorByRrset {
        Box::new(
            self.iter_by_node()
                .flat_map(|(name, rrsets)| rrsets.map(move |rrset| (name, rrset))),
        )
    }

    /// Checks a zone for semantic errors and warnings. See
    /// [`ValidationIssue`] for the kinds of errors and warnings that
    /// this method returns.
    ///
    /// This method is provided and should *not* be overridden.
    fn validate(&self) -> Result<Vec<ValidationIssue>, Error> {
        validation::validate(self)
    }
}

/// The iterator type produced by [`Zone::iter_by_node`].
pub type IteratorByNode<'a> =
    Box<dyn Iterator<Item = (&'a Name, Box<dyn Iterator<Item = IteratedRrset<'a>> + 'a>)> + 'a>;

/// The iterator type produced by [`Zone::iter_by_rrset`].
pub type IteratorByRrset<'a> = Box<dyn Iterator<Item = (&'a Name, IteratedRrset<'a>)> + 'a>;

////////////////////////////////////////////////////////////////////////
// ZONE LOOKUP TYPES                                                  //
////////////////////////////////////////////////////////////////////////

/// Options provided to [`Zone::lookup`], [`Zone::lookup_addrs`], and
/// [`Zone::lookup_all`].
#[derive(Clone, Debug, Default)]
pub struct LookupOptions {
    /// Disables wrong-zone checks on the looked-up domain name.
    ///
    /// If enabled, then the [`Zone`] implementation is not required to
    /// check that the looked-up name is within the zone's hierarchy,
    /// since the caller guarantees that this is the case. For example,
    /// if the caller has found the [`Zone`] through a
    /// [`Catalog`](`super::Catalog`) lookup for a name and is now
    /// looking up the same name in the zone, then the caller can make
    /// this guarantee; turning on this option eliminates a redundant
    /// check for increased performance. If the caller fails to uphold
    /// the guarantee, then the [`Zone`] implementation may panic or
    /// return incorrect data. However, it **must not** cause undefined
    /// behavior.
    ///
    /// If disabled, then the [`Zone`] implementation **must** check
    /// that the looked-up name is within the zone (that is, that it is
    /// equal to or a subdomain of the zone's name). If it is not, it
    /// **must** return [`LookupResult::WrongZone`],
    /// [`LookupAddrsResult::WrongZone`], or
    /// [`LookupAllResult::WrongZone`] as appropriate.
    ///
    /// A [`Zone`] implementation **may** choose to perform the check
    /// regardless of this option.
    pub unchecked: bool,

    /// Enables searches below zone cuts (and consequently disables
    /// referral generation).
    ///
    /// If enabled, then the [`Zone`] implementation **must** ignore
    /// zone cuts (signified by NS records) at or above the looked-up
    /// name. Use this to search for glue records.
    ///
    /// If disabled, then the [`Zone`] implementation **must** detect
    /// zone cuts and return [`LookupResult::Referral`],
    /// [`LookupAddrsResult::Referral`], or
    /// [`LookupAllResult::Referral`] as appropriate.
    pub search_below_cuts: bool,
}

/// The result of a lookup of records of a specific type (see
/// [`Zone::lookup`]).
#[derive(Debug)]
pub enum LookupResult<'a> {
    /// The desired records were found.
    Found(Found<'a, SingleRrset<'a>>),

    /// No records were found, but a CNAME record was present.
    Cname(Cname<'a>),

    /// The lookup encountered an NS RRset and would therefore leave
    /// authoritative data.
    Referral(Referral<'a>),

    /// A node with the given name exists, but it has no records of the
    /// desired type.
    NoRecords(NoRecords<'a>),

    /// The domain name does not exist.
    NxDomain,

    /// The provided name is not within the zone's hierarchy.
    WrongZone,
}

/// The result of a lookup of all address (A or AAAA) records (see
/// [`Zone::lookup_addrs`].
#[derive(Debug)]
pub enum LookupAddrsResult<'a> {
    /// The name exists; any available addresses are returned.
    Found(Found<'a, Addresses<'a>>),

    /// No records were found, but a CNAME record was present.
    Cname(Cname<'a>),

    /// The lookup encountered an NS RRset and would therefore leave
    /// authoritative data.
    Referral(Referral<'a>),

    /// The domain name does not exist.
    NxDomain,

    /// The provided name is not within the zone's hierarchy.
    WrongZone,
}

/// The result of a lookup of *all* records for a name (see
/// [`Zone::lookup_all`]).
#[derive(Debug)]
pub enum LookupAllResult<'a> {
    /// The name exists; any available addresses are returned.
    Found(Found<'a, Box<dyn RrsetIterator<'a> + 'a>>),

    /// The lookup encountered an NS RRset and would therefore leave
    /// authoritative data.
    Referral(Referral<'a>),

    /// The domain name does not exist.
    NxDomain,

    /// The provided name is not within the zone's hierarchy.
    WrongZone,
}

/// Data returned when a lookup finds the requested data.
#[derive(Clone, Debug)]
pub struct Found<'a, R> {
    /// The data (an RRset or multiple RRsets) that were looked up.
    pub data: R,

    /// If this result was synthesized from a wildcard domain name,
    /// then this indicates the source of synthesis.
    pub source_of_synthesis: Option<Cow<'a, Name>>,
}

/// Data returned when a lookup finds a CNAME at the target domain (and
/// other records were requested).
#[derive(Clone, Debug)]
pub struct Cname<'a> {
    /// The CNAME RRset found at the target domain name.
    pub rrset: SingleRrset<'a>,

    /// If this result was synthesized from a wildcard domain name, then
    /// this indicates the source of synthesis.
    pub source_of_synthesis: Option<Cow<'a, Name>>,
}

/// Data returned when a lookup encounters a zone cut.
#[derive(Clone, Debug)]
pub struct Referral<'a> {
    /// The domain name of the child zone, i.e., the name at which NS
    /// records were found.
    pub child_zone: Cow<'a, Name>,

    /// The NS RRset found at the zone cut.
    pub ns_rrset: SingleRrset<'a>,
}

/// Data returned when a single-type lookup finds the target domain
/// name, but it does not own matching data.
#[derive(Clone, Debug)]
pub struct NoRecords<'a> {
    /// If this result was synthesized from a wildcard domain name, then
    /// this indicates the source of synthesis.
    pub source_of_synthesis: Option<Cow<'a, Name>>,
}

/// A single RRset returned by a lookup call.
///
/// This does not include the record's owner, class or type; these will
/// be known from context.
#[derive(Clone, Debug)]
pub struct SingleRrset<'a> {
    pub ttl: Ttl,
    pub rdatas: Cow<'a, RdataSet>,
}

/// Address RRsets returned by [`Zone::lookup_addrs`].
#[derive(Clone, Debug)]
pub struct Addresses<'a> {
    pub a_rrset: Option<SingleRrset<'a>>,
    pub aaaa_rrset: Option<SingleRrset<'a>>,
}

/// One of many RRsets returned by a lookup call or zone iterator.
///
/// The owner and class are omitted, since they will be known from
/// context.
#[derive(Clone, Debug)]
pub struct IteratedRrset<'a> {
    pub rr_type: Type,
    pub ttl: Ttl,
    pub rdatas: Cow<'a, RdataSet>,
}

impl<'a> From<IteratedRrset<'a>> for SingleRrset<'a> {
    fn from(iterated: IteratedRrset<'a>) -> SingleRrset<'a> {
        SingleRrset {
            ttl: iterated.ttl,
            rdatas: iterated.rdatas,
        }
    }
}

/// An iterator that produces RRsets, as returned by
/// [`Zone::lookup_all`].
///
/// This is to require such iterators to implement [`Debug`], so that
/// [`LookupAllResult`] itself can also implement [`Debug`].
pub trait RrsetIterator<'a>: Iterator<Item = IteratedRrset<'a>> + Debug {}

impl<'a, I> RrsetIterator<'a> for I where I: Iterator<Item = IteratedRrset<'a>> + Debug {}

////////////////////////////////////////////////////////////////////////
// GLUE POLICIES                                                      //
////////////////////////////////////////////////////////////////////////

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GluePolicy {
    Narrow,
    Wide,
}
