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

//! Implementation of the RRset-related data structures [`Rrset`] and
//! [`RrsetList`].

use std::fmt;
use std::iter::FusedIterator;

use super::{Rdata, Ttl, Type};
use crate::class::Class;

////////////////////////////////////////////////////////////////////////
// RRSETS                                                             //
////////////////////////////////////////////////////////////////////////

/// A data structure for resource record sets.
///
/// [RFC 2181 § 5] defined an RRset as a group of records with the same
/// label, class, and type, and also stipulated that all records in an
/// RRset have the same TTL. Since DNS records are lookup up through
/// RRsets and later DNS specifications like DNSSEC approach DNS data
/// through the concept, it makes sense for us to store DNS records
/// grouped into RRsets. Multiple records are stored in the same
/// [`Rrset`] structure by setting their common [`Type`], [`Class`],
/// and [`Ttl`], and then pushing their [`Rdata`]s, one for each record.
/// The label of the [`Rrset`] is not stored in the structure itself,
/// but rather is kept track of separately by its owner (or the owner of
/// the [`RrsetList`] it is part of).
///
/// [RFC 2181 § 5]: https://datatracker.ietf.org/doc/html/rfc2181#section-5
pub struct Rrset {
    pub rr_type: Type,
    pub class: Class,
    pub ttl: Ttl,
    rdatas: Vec<u8>,
}

impl Rrset {
    /// Creates a new [`Rrset`] with the given RR type, class, and TTL.
    /// It will initially contain no record data.
    pub fn new(rr_type: Type, class: Class, ttl: Ttl) -> Self {
        Self {
            rr_type,
            class,
            ttl,
            rdatas: Vec::new(),
        }
    }

    /// Adds an [`Rdata`] to this [`Rrset`]. Following the behavior of
    /// other nameservers, we silently discard [`Rdata`] that is already
    /// present in the [`Rrset`].
    pub fn push_rdata(&mut self, rdata: &Rdata) {
        for existing_rdata in self.rdatas() {
            if rdata.equals(existing_rdata, self.rr_type) {
                return;
            }
        }
        self.rdatas.reserve(2 + rdata.len());
        self.rdatas
            .extend_from_slice(&(rdata.len() as u16).to_ne_bytes());
        self.rdatas.extend_from_slice(rdata.octets());
    }

    /// Returns an iterator over the [`Rdata`] of this `Rrset`.
    pub fn rdatas(&self) -> RdataIterator {
        RdataIterator {
            cursor: &self.rdatas,
        }
    }
}

/// An iterator over the [`Rdata`] of an [`Rrset`].
pub struct RdataIterator<'a> {
    cursor: &'a [u8],
}

impl<'a> Iterator for RdataIterator<'a> {
    type Item = &'a Rdata;

    fn next(&mut self) -> Option<Self::Item> {
        let len_octets: &[u8; 2] = self.cursor.get(0..2)?.try_into().ok()?;
        let len = u16::from_ne_bytes(*len_octets) as usize;
        if let Some(rdata) = self.cursor.get(2..len + 2) {
            self.cursor = &self.cursor[len + 2..];
            Some(Rdata::from_unchecked(rdata))
        } else {
            None
        }
    }
}

impl FusedIterator for RdataIterator<'_> {}

impl fmt::Debug for Rrset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Rrset")
            .field("rr_type", &self.rr_type)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("rdatas", &RdatasDebugger(self))
            .finish()
    }
}

/// A wrapper around an [`Rrset`] to print debug output for its
/// [`Rdata`]s.
struct RdatasDebugger<'a>(&'a Rrset);

impl fmt::Debug for RdatasDebugger<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut list = f.debug_list();
        for rdata in self.0.rdatas() {
            list.entry(&format_args!("{:?}", rdata));
        }
        list.finish()
    }
}

////////////////////////////////////////////////////////////////////////
// RRSET LISTS                                                        //
////////////////////////////////////////////////////////////////////////

/// A data structure to contain all of the [`Rrset`]s of various
/// [`Type`]s at a node in the DNS tree hierarchy. Individual records
/// are added using the [`RrsetList::add`] method; the various
/// [`Rrset`]s are constructed and managed internally.
#[derive(Debug, Default)]
pub struct RrsetList {
    rrsets: Vec<Rrset>,
}

impl RrsetList {
    /// Returns a new, empty [`RrsetList`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds a resource record to the [`RrsetList`].
    ///
    /// This will fail if the [`Class`] of the new record does not match
    /// the rest of the records in the [`RrsetList`], and if the [`Ttl`]
    /// of the new record does match the rest of the records in its
    /// [`Rrset`].
    ///
    /// Note that this does not validate the [`Rdata`] with respect to
    /// the [`Type`]. In addition, if the target [`Rrset`] exists and
    /// already contains [`Rdata`] equal to the provided [`Rdata`] (see
    /// [`Rdata::equals`]), then following the behavior of other
    /// nameservers, the new [`Rdata`] is silently ignored.
    pub fn add(
        &mut self,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<(), RrsetListAddError> {
        if !self.rrsets.is_empty() && self.rrsets[0].class != class {
            return Err(RrsetListAddError::ClassMismatch);
        }
        match self.rrsets.binary_search_by_key(&rr_type, |r| r.rr_type) {
            Ok(index) => {
                let rrset = &mut self.rrsets[index];
                if rrset.ttl != ttl {
                    Err(RrsetListAddError::TtlMismatch)
                } else {
                    rrset.push_rdata(rdata);
                    Ok(())
                }
            }
            Err(index) => {
                let mut rrset = Rrset::new(rr_type, class, ttl);
                rrset.push_rdata(rdata);
                self.rrsets.insert(index, rrset);
                Ok(())
            }
        }
    }

    /// Looks up the [`Rrset`] of type `rr_type` in the [`RrsetList`].
    pub fn lookup(&self, rr_type: Type) -> Option<&Rrset> {
        // TODO: is it worth using the binary search?
        self.rrsets
            .binary_search_by_key(&rr_type, |r| r.rr_type)
            .map(|index| &self.rrsets[index])
            .ok()
    }

    /// Returns an iterator over the [`Rrset`]s of the `RrsetList`.
    pub fn iter(&self) -> std::slice::Iter<Rrset> {
        self.rrsets.iter()
    }

    /// Returns the number of [`Rrset`]s in the `RrsetList`.
    pub fn len(&self) -> usize {
        self.rrsets.len()
    }

    /// Returns whether the `RrsetList` is empty.
    pub fn is_empty(&self) -> bool {
        self.rrsets.is_empty()
    }
}

/// An error signaling that a record cannot be added to an [`RrsetList`]
/// since its [`Ttl`] differs from the rest of the records in its
/// [`Rrset`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RrsetListAddError {
    /// A record cannot be added because its [`Class`] differs from the
    /// rest of the records in the [`RrsetList`].
    ClassMismatch,

    /// A record cannot be added because its [`Ttl`] differs from the
    /// rest of the records in its [`Rrset`].
    TtlMismatch,
}

impl fmt::Display for RrsetListAddError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::ClassMismatch => f.write_str("class mismatch"),
            Self::TtlMismatch => f.write_str("TTL mismatch"),
        }
    }
}

impl std::error::Error for RrsetListAddError {}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrset_works() {
        let loopback1: &Rdata = (&[127, 0, 0, 1]).try_into().unwrap();
        let loopback2: &Rdata = (&[127, 0, 0, 2]).try_into().unwrap();
        let mut rrset = Rrset::new(Type::A, Class::IN, Ttl::from(3600));
        rrset.push_rdata(loopback1);
        rrset.push_rdata(loopback2);
        assert_eq!(rrset.rr_type, Type::A);
        assert_eq!(rrset.class, Class::IN);
        assert_eq!(u32::from(rrset.ttl), 3600);
        assert_eq!(
            rrset.rdatas().map(Rdata::octets).collect::<Vec<_>>(),
            [loopback1.octets(), loopback2.octets()],
        );
    }

    #[test]
    fn rrset_ignores_duplicates() {
        let rdata1: &Rdata = (&[2, 0, b'a', 0]).try_into().unwrap();
        let rdata2: &Rdata = (&[2, 0, b'A', 0]).try_into().unwrap();

        let push_rdatas = |rrset: &mut Rrset| {
            rrset.push_rdata(rdata1);
            rrset.push_rdata(rdata2);
            rrset.push_rdata(rdata1);
        };

        // For e.g. A records, bitwise comparison should always be used.
        let mut a_rrset = Rrset::new(Type::A, Class::IN, Ttl::from(3600));
        push_rdatas(&mut a_rrset);
        assert_eq!(
            a_rrset.rdatas().map(Rdata::octets).collect::<Vec<_>>(),
            [rdata1.octets(), rdata2.octets()],
        );

        // But for RR types embedding domain names *preceding* RFC 3597,
        // case-insensitive name comparison needs to be used. (See the
        // cmp module for details.)
        let mut cname_rrset = Rrset::new(Type::CNAME, Class::IN, Ttl::from(3600));
        push_rdatas(&mut cname_rrset);
        assert_eq!(
            cname_rrset.rdatas().map(Rdata::octets).collect::<Vec<_>>(),
            [rdata1.octets()],
        );
    }

    #[test]
    fn rrsetlist_works() {
        let loopback1: &Rdata = (&[127, 0, 0, 1]).try_into().unwrap();
        let loopback2: &Rdata = (&[127, 0, 0, 2]).try_into().unwrap();
        let domain: &Rdata = b"\x04test\x00".try_into().unwrap();
        let mut rrsets = RrsetList::new();
        rrsets
            .add(Type::A, Class::IN, Ttl::from(3600), loopback1)
            .unwrap();
        rrsets
            .add(Type::A, Class::IN, Ttl::from(3600), loopback2)
            .unwrap();
        rrsets
            .add(Type::CNAME, Class::IN, Ttl::from(7200), domain)
            .unwrap();

        let a_rrset = rrsets.lookup(Type::A).unwrap();
        assert_eq!(
            a_rrset.rdatas().map(Rdata::octets).collect::<Vec<_>>(),
            [loopback1.octets(), loopback2.octets()],
        );
        let cname_rrset = rrsets.lookup(Type::CNAME).unwrap();
        assert_eq!(
            cname_rrset.rdatas().map(Rdata::octets).collect::<Vec<_>>(),
            [domain.octets()],
        );
        assert!(rrsets.lookup(Type::AAAA).is_none());
    }

    #[test]
    fn rrsetlist_rejects_class_mismatch() {
        let domain: &Rdata = b"\x04test\x00".try_into().unwrap();
        let mut rrsets = RrsetList::new();
        rrsets
            .add(Type::NS, Class::IN, Ttl::from(3600), domain)
            .unwrap();
        assert_eq!(
            rrsets.add(Type::CNAME, Class::CH, Ttl::from(3600), domain),
            Err(RrsetListAddError::ClassMismatch)
        );
    }

    #[test]
    fn rrsetlist_rejects_ttl_mismatch() {
        let domain: &Rdata = b"\x04test\x00".try_into().unwrap();
        let mut rrsets = RrsetList::new();
        rrsets
            .add(Type::NS, Class::IN, Ttl::from(3600), domain)
            .unwrap();
        assert_eq!(
            rrsets.add(Type::NS, Class::IN, Ttl::from(7200), domain),
            Err(RrsetListAddError::TtlMismatch)
        );
    }
}
