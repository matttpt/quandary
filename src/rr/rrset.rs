// Copyright 2021 Matthew Ingwersen.
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

//! Implementation of RRset-related data structures and types.

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::iter::FusedIterator;
use std::ops::Deref;
use std::str::FromStr;

use crate::class::Class;
use crate::util::Caseless;

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
        self.rdatas.extend_from_slice(rdata);
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
/// [`Rrset].
#[derive(Debug, Eq, PartialEq)]
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
            Self::ClassMismatch => f.write_str("CLASS mismatch"),
            Self::TtlMismatch => f.write_str("TTL mismatch"),
        }
    }
}

impl std::error::Error for RrsetListAddError {}

////////////////////////////////////////////////////////////////////////
// RDATA                                                              //
////////////////////////////////////////////////////////////////////////

/// A type for record RDATA.
///
/// The RDATA of a record is limited to 65,535 octets. The `Rdata` type
/// is a wrapper over `[u8]` that can only be constructed if the
/// underlying data has a valid length.
#[derive(Eq, PartialEq)]
#[repr(transparent)]
pub struct Rdata {
    octets: [u8],
}

impl Rdata {
    /// Converts a `&[u8]` to a `&Rdata`, without checking the length;
    /// for internal use only.
    fn from_unchecked(octets: &[u8]) -> &Self {
        unsafe { &*(octets as *const [u8] as *const Self) }
    }

    /// Returns the underlying octet slice.
    pub fn octets(&self) -> &[u8] {
        self
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Rdata {
    type Error = RdataTooLongError;

    fn try_from(octets: &'a [u8]) -> Result<Self, Self::Error> {
        if octets.len() > (u16::MAX as usize) {
            Err(RdataTooLongError)
        } else {
            Ok(Rdata::from_unchecked(octets))
        }
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for &'a Rdata {
    type Error = RdataTooLongError;

    fn try_from(octets: &'a [u8; N]) -> Result<Self, Self::Error> {
        octets[..].try_into()
    }
}

impl Deref for Rdata {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.octets
    }
}

/// An error signaling that a `&[u8]` cannot be converted to a `&Rdata`
/// because it is too long.
#[derive(Debug, Eq, PartialEq)]
pub struct RdataTooLongError;

impl fmt::Display for RdataTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RDATA is too long")
    }
}

impl std::error::Error for RdataTooLongError {}

////////////////////////////////////////////////////////////////////////
// RR TYPES                                                           //
////////////////////////////////////////////////////////////////////////

/// Represents the RR type of a DNS record.
///
/// An RR type is represented on the wire as an unsigned 16-bit integer.
/// Hence this is basically a wrapper around `u16` with nice
/// [`Debug`](fmt::Debug), [`Display`](fmt::Display), and [`FromStr`]
/// implementations for working with the common textual representations
/// of RR types. In addition, constants for common RR types (e.g.
/// [`Type::A`] are provided.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Type(u16);

impl Type {
    pub const A: Type = Type(1);
    pub const NS: Type = Type(2);
    pub const MD: Type = Type(3);
    pub const MF: Type = Type(4);
    pub const CNAME: Type = Type(5);
    pub const SOA: Type = Type(6);
    pub const MB: Type = Type(7);
    pub const MG: Type = Type(8);
    pub const MR: Type = Type(9);
    pub const NULL: Type = Type(10);
    pub const WKS: Type = Type(11);
    pub const PTR: Type = Type(12);
    pub const HINFO: Type = Type(13);
    pub const MINFO: Type = Type(14);
    pub const MX: Type = Type(15);
    pub const TXT: Type = Type(16);
    pub const AAAA: Type = Type(28);
    pub const SRV: Type = Type(33);
}

impl From<u16> for Type {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<Type> for u16 {
    fn from(rr_type: Type) -> Self {
        rr_type.0
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match Caseless(text) {
            Caseless("A") => Ok(Self::A),
            Caseless("NS") => Ok(Self::NS),
            Caseless("MD") => Ok(Self::MD),
            Caseless("MF") => Ok(Self::MF),
            Caseless("CNAME") => Ok(Self::CNAME),
            Caseless("SOA") => Ok(Self::SOA),
            Caseless("MB") => Ok(Self::MB),
            Caseless("MG") => Ok(Self::MG),
            Caseless("MR") => Ok(Self::MR),
            Caseless("NULL") => Ok(Self::NULL),
            Caseless("WKS") => Ok(Self::WKS),
            Caseless("PTR") => Ok(Self::PTR),
            Caseless("HINFO") => Ok(Self::HINFO),
            Caseless("MINFO") => Ok(Self::MINFO),
            Caseless("MX") => Ok(Self::MX),
            Caseless("TXT") => Ok(Self::TXT),
            Caseless("AAAA") => Ok(Self::AAAA),
            Caseless("SRV") => Ok(Self::SRV),
            _ => {
                if text
                    .get(0..4)
                    .map_or(false, |prefix| prefix.eq_ignore_ascii_case("TYPE"))
                {
                    text[4..]
                        .parse::<u16>()
                        .map(Self::from)
                        .or(Err("type value is not a valid unsigned 16-bit integer"))
                } else {
                    Err("unknown type")
                }
            }
        }
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::A => f.write_str("A"),
            Self::NS => f.write_str("NS"),
            Self::MD => f.write_str("MD"),
            Self::MF => f.write_str("MF"),
            Self::CNAME => f.write_str("CNAME"),
            Self::SOA => f.write_str("SOA"),
            Self::MB => f.write_str("MB"),
            Self::MG => f.write_str("MG"),
            Self::MR => f.write_str("MR"),
            Self::NULL => f.write_str("NULL"),
            Self::WKS => f.write_str("WKS"),
            Self::PTR => f.write_str("PTR"),
            Self::HINFO => f.write_str("HINFO"),
            Self::MINFO => f.write_str("MINFO"),
            Self::MX => f.write_str("MX"),
            Self::TXT => f.write_str("TXT"),
            Self::AAAA => f.write_str("AAAA"),
            Self::SRV => f.write_str("SRV"),
            Self(value) => write!(f, "TYPE{}", value), // RFC 3597 § 5
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TTLS                                                               //
////////////////////////////////////////////////////////////////////////

/// The time to live (TTL) of a DNS record.
///
/// There are contradictory definitions of the TTL field in [RFC 1035]
/// (see [erratum 2130]), so [RFC 2181 § 8] clarified that TTL values
/// are unsigned integers between 0 and 2³¹ - 1, inclusive. Because the
/// TTL field is 32 bits wide, the most significant bit is zero. A TTL
/// value received with the most significant bit set is interpreted as
/// zero.
///
/// This type wraps `u32` to implement [RFC 2181 § 8]. The public API
/// will only instantiate `Ttl` objects whose underlying `u32` values
/// have the most significant bit set to zero, and `Ttl::from(u32)`
/// treats TTL wire values with the most significant bit set as zero.
///
/// [Erratum 2130]: https://www.rfc-editor.org/errata/eid2130
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 2181 § 8]: https://datatracker.ietf.org/doc/html/rfc2181#section-8
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ttl(u32);

impl From<u32> for Ttl {
    fn from(raw: u32) -> Self {
        if raw > i32::MAX as u32 {
            Self(0)
        } else {
            Self(raw)
        }
    }
}

impl From<Ttl> for u32 {
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

impl fmt::Debug for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
        assert_eq!(rrset.rdatas().collect::<Vec<_>>(), [loopback1, loopback2]);
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
        assert_eq!(a_rrset.rdatas().collect::<Vec<_>>(), [rdata1, rdata2]);

        // But for RR types embedding domain names *preceding* RFC 3597,
        // case-insensitive name comparison needs to be used. (See the
        // cmp module for details.)
        let mut cname_rrset = Rrset::new(Type::CNAME, Class::IN, Ttl::from(3600));
        push_rdatas(&mut cname_rrset);
        assert_eq!(cname_rrset.rdatas().collect::<Vec<_>>(), [rdata1]);
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
        assert_eq!(a_rrset.rdatas().collect::<Vec<_>>(), [loopback1, loopback2]);
        let cname_rrset = rrsets.lookup(Type::CNAME).unwrap();
        assert_eq!(cname_rrset.rdatas().collect::<Vec<_>>(), [domain]);
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

    #[test]
    fn rdata_constructor_accepts_short_slices() {
        let quite_short = &[0, 1, 2, 3];
        let quite_short_rdata: &Rdata = quite_short.try_into().unwrap();
        assert_eq!(quite_short_rdata.octets(), quite_short);

        let almost_too_long = &[0; u16::MAX as usize];
        assert!(<&Rdata>::try_from(almost_too_long).is_ok());
    }

    #[test]
    fn rdata_constructor_rejects_long_slice() {
        let too_long = [0; u16::MAX as usize + 1];
        assert_eq!(<&Rdata>::try_from(&too_long[..]), Err(RdataTooLongError));
    }

    #[test]
    fn type_displays_according_to_rfc3597() {
        // TYPE65280 is from the private use range, so it should always
        // be unknown.
        let class = Type::from(0xff00);
        assert_eq!(class.to_string(), "TYPE65280");
    }

    #[test]
    fn type_parses_according_to_rfc3597() {
        // Again, TYPE65280 is from the private use range.
        let type_a: Type = "TYPE1".parse().unwrap();
        let type_65280: Type = "TYPE65280".parse().unwrap();
        assert_eq!(type_a, Type::A);
        assert_eq!(u16::from(type_65280), 65280);
    }

    #[test]
    fn small_ttls_are_not_modified() {
        let i32_max = i32::MAX as u32;
        assert_eq!(u32::from(Ttl::from(0)), 0);
        assert_eq!(u32::from(Ttl::from(23)), 23);
        assert_eq!(u32::from(Ttl::from(i32_max)), i32_max);
    }

    #[test]
    fn large_ttls_become_zero() {
        assert_eq!(u32::from(Ttl::from(i32::MAX as u32 + 1)), 0);
    }
}
