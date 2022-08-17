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

//! The [`RdataSet`] and [`RdataSetOwned`] structures.

use std::borrow::Borrow;
use std::fmt;
use std::iter::FusedIterator;
use std::ops::Deref;

use super::{Rdata, Type};

////////////////////////////////////////////////////////////////////////
// RDATASET STRUCTURE                                                 //
////////////////////////////////////////////////////////////////////////

/// Stores the RDATA for an RRset in a contiguous memory region.
///
/// This is designed to make it efficient to serve an RRset. In
/// particular, it allows many small RDATA (e.g. for an A RRset) to
/// reside in the same cache line.
///
/// The `RdataSet` structure is the borrowed view of stored RDATA and
/// can only be produced from the owned variant, [`RdataSetOwned`].
#[repr(transparent)]
pub struct RdataSet {
    inner: [u8],
}

impl RdataSet {
    /// Returns an iterator over the [`Rdata`] of this `RdataSet`.
    pub fn iter(&self) -> Iter {
        Iter {
            cursor: &self.inner,
        }
    }
}

impl ToOwned for RdataSet {
    type Owned = RdataSetOwned;

    fn to_owned(&self) -> Self::Owned {
        RdataSetOwned {
            inner: self.inner.into(),
        }
    }
}

impl fmt::Debug for RdataSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut list = f.debug_list();
        for rdata in self.iter() {
            list.entry(&format_args!("{:?}", rdata));
        }
        list.finish()
    }
}

////////////////////////////////////////////////////////////////////////
// RDATASET ITERATION                                                 //
////////////////////////////////////////////////////////////////////////

/// An iterator over the [`Rdata`] of an [`RdataSet`].
pub struct Iter<'a> {
    cursor: &'a [u8],
}

impl<'a> Iterator for Iter<'a> {
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

impl FusedIterator for Iter<'_> {}

////////////////////////////////////////////////////////////////////////
// OWNED RDATASET                                                     //
////////////////////////////////////////////////////////////////////////

/// The owned variant of [`RdataSet`].
#[derive(Clone, Default)]
pub struct RdataSetOwned {
    inner: Vec<u8>,
}

impl RdataSetOwned {
    /// Creates a new set initially containing no [`Rdata`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Copies an [`Rdata`] into this [`RdataSetOwned`]. The new
    /// [`Rdata`] is compared to the existing [`Rdata`] as if it were of
    /// the provided type and is not inserted if identical [`Rdata`] is
    /// already present. Returns whether the [`Rdata`] was inserted.
    pub fn insert(&mut self, rr_type: Type, rdata: &Rdata) -> bool {
        for existing_rdata in self.iter() {
            if rdata.equals(existing_rdata, rr_type) {
                return false;
            }
        }
        self.inner.reserve(2 + rdata.len());
        self.inner
            .extend_from_slice(&(rdata.len() as u16).to_ne_bytes());
        self.inner.extend_from_slice(rdata.octets());
        true
    }
}

impl Deref for RdataSetOwned {
    type Target = RdataSet;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.inner.as_slice() as *const [u8] as *const RdataSet) }
    }
}

impl Borrow<RdataSet> for RdataSetOwned {
    fn borrow(&self) -> &RdataSet {
        self.deref()
    }
}

impl AsRef<RdataSet> for RdataSetOwned {
    fn as_ref(&self) -> &RdataSet {
        self.deref()
    }
}

impl fmt::Debug for RdataSetOwned {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdata_set_owned_works() {
        let loopback1: &Rdata = (&[127, 0, 0, 1]).try_into().unwrap();
        let loopback2: &Rdata = (&[127, 0, 0, 2]).try_into().unwrap();
        let mut rdatas = RdataSetOwned::new();
        rdatas.insert(Type::A, loopback1);
        rdatas.insert(Type::A, loopback2);
        assert_eq!(
            rdatas.iter().map(Rdata::octets).collect::<Vec<_>>(),
            [loopback1.octets(), loopback2.octets()],
        );
    }

    #[test]
    fn rdata_set_owned_insert_ignores_duplicates() {
        let rdata1: &Rdata = (&[2, 0, b'a', 0]).try_into().unwrap();
        let rdata2: &Rdata = (&[2, 0, b'A', 0]).try_into().unwrap();

        let insert_rdatas = |rr_type, rdatas: &mut RdataSetOwned| {
            rdatas.insert(rr_type, rdata1);
            rdatas.insert(rr_type, rdata2);
            rdatas.insert(rr_type, rdata1);
        };

        // For e.g. A records, bitwise comparison should always be used.
        let mut a_rdatas = RdataSetOwned::new();
        insert_rdatas(Type::A, &mut a_rdatas);
        assert_eq!(
            a_rdatas.iter().map(Rdata::octets).collect::<Vec<_>>(),
            [rdata1.octets(), rdata2.octets()],
        );

        // But for RR types embedding domain names *preceding* RFC 3597,
        // case-insensitive name comparison needs to be used. (See the
        // cmp module for details.)
        let mut cname_rdatas = RdataSetOwned::new();
        insert_rdatas(Type::CNAME, &mut cname_rdatas);
        assert_eq!(
            cname_rdatas.iter().map(Rdata::octets).collect::<Vec<_>>(),
            [rdata1.octets()],
        );
    }
}
