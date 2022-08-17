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

//! Internal-use data structures for storing RRsets in memory.
//!
//! These types are used by Quandary's ready-made in-memory zone data
//! structures (e.g. [`HashMapTreeZone`](`super::HashMapTreeZone`).

use std::borrow::{Borrow, Cow};

use super::Error;
use crate::db::zone::{IteratedRrset, SingleRrset};
use crate::rr::{Rdata, RdataSetOwned, Ttl, Type};

/// Stores an RRset in memory.
///
/// This is missing the NAME and CLASS fields. It's not necessary to
/// store these, since that data is maintained by the zone data
/// structure itself.
#[derive(Clone, Debug)]
pub struct Rrset {
    pub rr_type: Type,
    pub ttl: Ttl,
    pub rdatas: RdataSetOwned,
}

impl<'a> From<&'a Rrset> for SingleRrset<'a> {
    fn from(rrset: &'a Rrset) -> SingleRrset<'a> {
        SingleRrset {
            ttl: rrset.ttl,
            rdatas: Cow::Borrowed(rrset.rdatas.borrow()),
        }
    }
}

impl<'a> From<&'a Rrset> for IteratedRrset<'a> {
    fn from(rrset: &'a Rrset) -> IteratedRrset<'a> {
        IteratedRrset {
            rr_type: rrset.rr_type,
            ttl: rrset.ttl,
            rdatas: Cow::Borrowed(rrset.rdatas.borrow()),
        }
    }
}

/// Stores all of the RRsets at a node in the DNS tree.
#[derive(Clone, Debug, Default)]
pub struct RrsetList {
    rrsets: Vec<Rrset>,
}

impl RrsetList {
    /// Adds a resource record to the [`RrsetList`].
    ///
    /// This will fail if the [`Ttl`] of the new record does match the
    /// rest of the records in its [`Rrset`].
    ///
    /// Note that this does not validate the [`Rdata`] with respect to
    /// the [`Type`]. In addition, if the target [`Rrset`] exists and
    /// already contains [`Rdata`] equal to the provided [`Rdata`] (see
    /// [`Rdata::equals`]), then the new [`Rdata`] is silently ignored.
    pub fn add(&mut self, rr_type: Type, ttl: Ttl, rdata: &Rdata) -> Result<(), Error> {
        match self.rrsets.binary_search_by_key(&rr_type, |r| r.rr_type) {
            Ok(index) => {
                let rrset = &mut self.rrsets[index];
                if rrset.ttl != ttl {
                    Err(Error::TtlMismatch)
                } else {
                    rrset.rdatas.insert(rr_type, rdata);
                    Ok(())
                }
            }
            Err(index) => {
                let mut rdatas = RdataSetOwned::new();
                rdatas.insert(rr_type, rdata);
                let rrset = Rrset {
                    rr_type,
                    ttl,
                    rdatas,
                };
                self.rrsets.insert(index, rrset);
                Ok(())
            }
        }
    }

    /// Looks up the [`Rrset`] of type `rr_type` in the `RrsetList`.
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
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrsetlist_works() {
        let loopback1: &Rdata = (&[127, 0, 0, 1]).try_into().unwrap();
        let loopback2: &Rdata = (&[127, 0, 0, 2]).try_into().unwrap();
        let domain: &Rdata = b"\x04test\x00".try_into().unwrap();
        let mut rrsets = RrsetList::default();
        rrsets.add(Type::A, Ttl::from(3600), loopback1).unwrap();
        rrsets.add(Type::A, Ttl::from(3600), loopback2).unwrap();
        rrsets.add(Type::CNAME, Ttl::from(7200), domain).unwrap();

        let a_rrset = rrsets.lookup(Type::A).unwrap();
        assert_eq!(
            a_rrset.rdatas.iter().map(Rdata::octets).collect::<Vec<_>>(),
            [loopback1.octets(), loopback2.octets()],
        );
        let cname_rrset = rrsets.lookup(Type::CNAME).unwrap();
        assert_eq!(
            cname_rrset
                .rdatas
                .iter()
                .map(Rdata::octets)
                .collect::<Vec<_>>(),
            [domain.octets()],
        );
        assert!(rrsets.lookup(Type::AAAA).is_none());
    }

    #[test]
    fn rrsetlist_rejects_ttl_mismatch() {
        let domain1: &Rdata = b"\x04test\x00".try_into().unwrap();
        let domain2: &Rdata = b"\x07invalid\x00".try_into().unwrap();
        let mut rrsets = RrsetList::default();
        rrsets.add(Type::NS, Ttl::from(3600), domain1).unwrap();
        assert_eq!(
            rrsets.add(Type::NS, Ttl::from(7200), domain2),
            Err(Error::TtlMismatch),
        );
    }
}
