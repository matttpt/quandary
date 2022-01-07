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

//! Helpers for the RR types from the original DNS specification, STD 13
//! ([RFC 1034] and [RFC 1035]).
//!
//! [RFC 1034]: https://datatracker.ietf.org/doc/html/rfc1034
//! [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035

use std::fmt;
use std::iter;
use std::net::Ipv4Addr;
use std::ops::Deref;

use super::helpers;
use super::{Rdata, RdataTooLongError, ReadRdataError};
use crate::name::Name;

////////////////////////////////////////////////////////////////////////
// STD 13 (RFC 1035 § 3.3) <CHARACTER-STRING> TYPE                    //
////////////////////////////////////////////////////////////////////////

/// A type for [RFC 1035 § 3.3] `<character-string>`s.
///
/// [RFC 1035 § 3.3] defines the `<character-string>` type, which (on
/// the wire) is a single length octet followed by that number of
/// octets. Thus the content of a `<character-string>` is limited to 255
/// octets. The `CharacterString` type is a wrapper over `[u8]` that can
/// only be constructed if the underlying data has length 255 or less.
///
/// [RFC 1035 § 3.3]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3
#[derive(Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CharacterString {
    octets: [u8],
}

impl CharacterString {
    /// Returns the underlying octet slice.
    pub fn octets(&self) -> &[u8] {
        self
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a CharacterString {
    type Error = CharacterStringTooLongError;

    fn try_from(octets: &'a [u8]) -> Result<Self, Self::Error> {
        if octets.len() > (u8::MAX as usize) {
            Err(CharacterStringTooLongError)
        } else {
            Ok(unsafe { &*(octets as *const [u8] as *const CharacterString) })
        }
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for &'a CharacterString {
    type Error = CharacterStringTooLongError;

    fn try_from(octets: &'a [u8; N]) -> Result<Self, Self::Error> {
        octets[..].try_into()
    }
}

impl Deref for CharacterString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.octets
    }
}

/// An error signaling that a `&[u8]` cannot be converted to a
/// `&CharacterString` because it is too long.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CharacterStringTooLongError;

impl fmt::Display for CharacterStringTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<character-string> is too long")
    }
}

impl std::error::Error for CharacterStringTooLongError {}

/// Validates the on-the-wire representation of a `<character-string>`
/// at the beginning of the provided buffer, returning the length of the
/// string on the wire when successful.
fn validate_character_string(octets: &[u8]) -> Result<usize, ReadRdataError> {
    if let Some(len) = octets.get(0) {
        let wire_len = 1 + *len as usize;
        if wire_len <= octets.len() {
            Ok(wire_len)
        } else {
            Err(ReadRdataError::Other)
        }
    } else {
        Err(ReadRdataError::Other)
    }
}

////////////////////////////////////////////////////////////////////////
// STD 13 (RFC 1035 § 3.3) - STANDARD RRS                             //
////////////////////////////////////////////////////////////////////////

/// Serializes an SOA record into the provided buffer.
///
/// Note that [RFC 1035 § 3.3.13] does not state whether REFRESH, RETRY,
/// and EXPIRE are signed or unsigned. BIND, NSD, and Knot all seem to
/// agree that they are unsigned, and that makes more sense than signed,
/// so we've gone with that!
///
/// [RFC 1035 § 3.3.13]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13
#[allow(clippy::too_many_arguments)]
pub fn serialize_soa(
    mname: &Name,
    rname: &Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
    buf: &mut Vec<u8>,
) {
    buf.reserve(20 + mname.wire_repr().len() + rname.wire_repr().len());
    buf.extend_from_slice(mname.wire_repr());
    buf.extend_from_slice(rname.wire_repr());
    buf.extend_from_slice(&serial.to_be_bytes());
    buf.extend_from_slice(&refresh.to_be_bytes());
    buf.extend_from_slice(&retry.to_be_bytes());
    buf.extend_from_slice(&expire.to_be_bytes());
    buf.extend_from_slice(&minimum.to_be_bytes());
}

/// Checks whether `rdata` is a valid serialized SOA record. This is for
/// the implementation of [`Rdata::validate`].
pub(super) fn validate_soa(rdata: &Rdata) -> Result<(), ReadRdataError> {
    let mname_len = Name::validate_uncompressed(rdata)?;
    let rname_len = Name::validate_uncompressed(&rdata[mname_len..])?;
    if rdata.len() == 20 + mname_len + rname_len {
        Ok(())
    } else {
        Err(ReadRdataError::Other)
    }
}

/// Validates and decompresses an SOA record. This is for the
/// implementation of [`Rdata::read`].
pub(super) fn read_soa(buf: &[u8], cursor: usize) -> Result<Box<Rdata>, ReadRdataError> {
    let (mname, mlen) = Name::try_from_compressed(buf, cursor)?;
    let (rname, rlen) = Name::try_from_compressed(buf, cursor + mlen)?;
    if buf.len() - cursor - mlen - rlen != 20 {
        Err(ReadRdataError::Other)
    } else {
        let mut rdata = Vec::with_capacity(mname.wire_repr().len() + rname.wire_repr().len() + 20);
        rdata.extend_from_slice(mname.wire_repr());
        rdata.extend_from_slice(rname.wire_repr());
        rdata.extend_from_slice(&buf[cursor + mlen + rlen..]);
        Ok(rdata.try_into().unwrap())
    }
}

/// Tests two on-the-wire SOA records *with the same length* for
/// equality, falling back to bitwise comparison if either is invalid.
/// This is for the implementation of [`Rdata::equals`].
pub(super) fn soas_equal(first: &Rdata, second: &Rdata) -> bool {
    assert!(first.len() == second.len());
    match helpers::test_n_name_fields(first, second, 2) {
        Some(Some(len)) => {
            if first.len() - len != 20 {
                // The remaining fields are not the right length.
                // Fall back to bitwise comparison.
                first == second
            } else {
                // Compare the remaining fields bitwise.
                first[len..] == second[len..]
            }
        }
        Some(None) => false,
        None => first == second,
    }
}

/// Serializes a WKS record into the provided buffer.
pub fn serialize_wks(address: Ipv4Addr, protocol: u8, ports: &[u16], buf: &mut Vec<u8>) {
    let len = match ports.iter().max() {
        Some(highest_port) => (*highest_port as usize) / 8 + 1,
        None => 0,
    };
    buf.reserve(5 + len);
    buf.extend_from_slice(&address.octets());
    buf.push(protocol);
    let start_index = buf.len();
    buf.extend(iter::repeat(0).take(len));
    for port in ports {
        let offset = (*port as usize) / 8;
        let mask = 1 << (port % 8);
        buf[start_index + offset] |= mask;
    }
}

/// Checks whether `rdata` is a valid serialized WKS record. This is for
/// the implementation of [`Rdata::validate`] and [`Rdata::read`].
pub(super) fn validate_wks(rdata: &Rdata) -> Result<(), ReadRdataError> {
    if rdata.len() >= 5 {
        Ok(())
    } else {
        Err(ReadRdataError::Other)
    }
}

/// Serializes an HINFO record into the provided buffer.
pub fn serialize_hinfo(cpu: &CharacterString, os: &CharacterString, buf: &mut Vec<u8>) {
    buf.reserve(2 + cpu.len() + os.len());
    buf.push(cpu.len() as u8);
    buf.extend_from_slice(cpu);
    buf.push(os.len() as u8);
    buf.extend_from_slice(os);
}

/// Checks whether `rdata` is a valid serialized HINFO record. This is
/// for the implementation of [`Rdata::validate`] and [`Rdata::read`].
pub(super) fn validate_hinfo(rdata: &Rdata) -> Result<(), ReadRdataError> {
    let cpu_len = validate_character_string(rdata)?;
    let os_len = validate_character_string(&rdata[cpu_len..])?;
    if rdata.len() == cpu_len + os_len {
        Ok(())
    } else {
        Err(ReadRdataError::Other)
    }
}

/// Serializes an MINFO record into the provided buffer.
pub fn serialize_minfo(rmailbx: &Name, emailbx: &Name, buf: &mut Vec<u8>) {
    buf.reserve(rmailbx.wire_repr().len() + emailbx.wire_repr().len());
    buf.extend_from_slice(rmailbx.wire_repr());
    buf.extend_from_slice(emailbx.wire_repr());
}

/// Checks whether `rdata` is a valid serialized MINFO record. This is
/// for the implementation of [`Rdata::validate`].
pub(super) fn validate_minfo(rdata: &Rdata) -> Result<(), ReadRdataError> {
    let rmailbx_len = Name::validate_uncompressed(rdata)?;
    Name::validate_uncompressed_all(&rdata[rmailbx_len..]).map_err(Into::into)
}

/// Validates and decompresses an MINFO record. This is for the
/// implementation of [`Rdata::read`].
pub(super) fn read_minfo(buf: &[u8], cursor: usize) -> Result<Box<Rdata>, ReadRdataError> {
    let (rmailbx, rlen) = Name::try_from_compressed(buf, cursor)?;
    let (emailbx, elen) = Name::try_from_compressed(buf, cursor + rlen)?;
    if buf.len() - cursor != rlen + elen {
        Err(ReadRdataError::Other)
    } else {
        let mut rdata = Vec::with_capacity(rmailbx.wire_repr().len() + emailbx.wire_repr().len());
        rdata.extend_from_slice(rmailbx.wire_repr());
        rdata.extend_from_slice(emailbx.wire_repr());
        Ok(rdata.try_into().unwrap())
    }
}

/// Tests two on-the-wire MINFO records for equality, falling back to
/// bitwise comparison if either is invalid. This is for the
/// implementation of [`Rdata::equals`].
pub(super) fn minfos_equal(first: &Rdata, second: &Rdata) -> bool {
    match helpers::test_n_name_fields(first, second, 2) {
        Some(Some(len)) if len == first.len() => true,
        Some(Some(_)) => first == second, // Invalid since there's extra data
        Some(None) => false,
        None => first == second,
    }
}

/// Serializes an MX record into the provided buffer.
pub fn serialize_mx(preference: u16, name: &Name, buf: &mut Vec<u8>) {
    buf.reserve(2 + name.wire_repr().len());
    buf.extend_from_slice(&preference.to_be_bytes());
    buf.extend_from_slice(name.wire_repr());
}

/// Checks whether `rdata` is a valid serialized MX record. This is for
/// the implementation of [`Rdata::validate`].
pub(super) fn validate_mx(rdata: &Rdata) -> Result<(), ReadRdataError> {
    if let Some(exchange_octets) = rdata.get(2..) {
        Name::validate_uncompressed_all(exchange_octets).map_err(Into::into)
    } else {
        Err(ReadRdataError::Other)
    }
}

/// Validates and decompresses an MX record. This is for the
/// implementation of [`Rdata::read`].
pub(super) fn read_mx(buf: &[u8], cursor: usize) -> Result<Box<Rdata>, ReadRdataError> {
    if buf.len() - cursor < 2 {
        Err(ReadRdataError::Other)
    } else {
        let (exchange, len) = Name::try_from_compressed(buf, cursor + 2)?;
        if buf.len() - cursor != len + 2 {
            Err(ReadRdataError::Other)
        } else {
            let mut rdata = Vec::with_capacity(2 + exchange.wire_repr().len());
            rdata.extend_from_slice(&buf[cursor..cursor + 2]);
            rdata.extend_from_slice(exchange.wire_repr());
            Ok(rdata.try_into().unwrap())
        }
    }
}

/// Tests two on-the-wire MX records *with the same length* for
/// equality. If either contains an invalid domain name, this falls back
/// to bitwise comparison. This is for the implementation of
/// [`Rdata::equals`].
pub(super) fn mxs_equal(first: &Rdata, second: &Rdata) -> bool {
    assert!(first.len() == second.len());
    if first.len() > 2 {
        // Note that if names_equal falls back to bitwise comparison,
        // then we did a bitwise comparison of the whole thing, so we
        // still did what we said we would!
        first[0..2] == second[0..2] && helpers::names_equal(&first[2..], &second[2..])
    } else {
        // Invalid records; do a bitwise comparison.
        first == second
    }
}

/// A helper to serialize DNS TXT records.
///
/// [RFC 1035 § 3.3.14] defines the TXT RDATA format as one or more
/// `<character-string>`s (see [CharacterString]). This helper allows
/// one to serialize a TXT RDATA by inputting `<character-string>`s
/// one by one using the [`TxtBuilder::try_push`] method. The
/// `<character-string>`s are written out to the buffer provided to
/// [`TxtBuilder::new`] when the `TxtBuilder` is constructed. The
/// `TxtBuilder` keeps track of the number of octets written, and
/// [`TxtBuilder::try_push`] will fail if the written length would
/// exceed the 65,535-octet limit for DNS RDATA. When all
/// `<character-string>`s are written, no finalization is necessary.
///
/// ```
/// use quandary::rr::rdata::TxtBuilder;
///
/// // Serialize a TXT record with two <character-string>s.
/// let mut rdata = Vec::new();
/// let mut builder = TxtBuilder::new(&mut rdata);
/// builder.try_push(b"a character string".try_into().unwrap()).unwrap();
/// builder.try_push(b"another string".try_into().unwrap()).unwrap();
///
/// // Now do something with the buffer.
/// println!("{:?}", rdata);
/// ```
///
/// [RFC 1035 § 3.3.14]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
pub struct TxtBuilder<'a> {
    buf: &'a mut Vec<u8>,
    octets_written: usize,
}

impl<'a> TxtBuilder<'a> {
    /// Constructs a new `TxtBuilder` that will serialize
    /// `<character-string>`s into the provided buffer.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self {
            buf,
            octets_written: 0,
        }
    }

    /// Attempts to serialize an additional `<character-string>` into
    /// the underlying buffer. If this would exceed the maximum RDATA
    /// length of 65,535 octets, then this will fail.
    pub fn try_push(
        &mut self,
        character_string: &CharacterString,
    ) -> Result<(), RdataTooLongError> {
        if self.octets_written + character_string.len() + 1 > (u16::MAX as usize) {
            Err(RdataTooLongError)
        } else {
            self.buf.reserve(1 + character_string.len());
            self.buf.push(character_string.len() as u8);
            self.buf.extend_from_slice(character_string);
            self.octets_written += character_string.len() + 1;
            Ok(())
        }
    }
}

/// Checks whether `rdata` is a valid serialized TXT record. This is for
/// the implementation of [`Rdata::validate`] and [`Rdata::read`].
pub(super) fn validate_txt(rdata: &Rdata) -> Result<(), ReadRdataError> {
    if rdata.is_empty() {
        // Per RFC 1035 § 3.3.14, a TXT record must have at least one
        // <character-string>.
        return Err(ReadRdataError::Other);
    }

    // NOTE: since validate_character_string() will not return a zero
    // length, this loop will eventually end.
    let mut offset = 0;
    while offset < rdata.len() {
        offset += validate_character_string(&rdata[offset..])?;
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////
// STD 13 (RFC 1035 § 3.4) - INTERNET-SPECIFIC RRS                    //
////////////////////////////////////////////////////////////////////////

/// Serializes an A record into the provided buffer.
pub fn serialize_a(address: Ipv4Addr, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&address.octets())
}

/// Checks whether `rdata` is a valid serialized A record. This is for
/// the implementation of [`Rdata::validate`] and [`Rdata::read`].
pub(super) fn validate_a(rdata: &Rdata) -> Result<(), ReadRdataError> {
    if rdata.len() == 4 {
        Ok(())
    } else {
        Err(ReadRdataError::Other)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_string_constructor_accepts_short_slices() {
        let quite_short = b"abcd";
        let quite_short_cs: &CharacterString = quite_short.try_into().unwrap();
        assert_eq!(quite_short_cs.octets(), quite_short);

        let almost_too_long = &[0; u8::MAX as usize];
        assert!(<&Rdata>::try_from(almost_too_long).is_ok());
    }

    #[test]
    fn character_string_constructor_rejects_long_slice() {
        let too_long = [0; u8::MAX as usize + 1];
        assert_eq!(
            <&CharacterString>::try_from(&too_long[..]),
            Err(CharacterStringTooLongError)
        );
    }

    #[test]
    fn serialize_wks_works() {
        let mut vec = Vec::new();
        serialize_wks("127.0.0.1".parse().unwrap(), 6, &[80, 25], &mut vec);
        assert_eq!(
            vec,
            b"\x7f\x00\x00\x01\x06\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x01"
        );
    }

    #[test]
    fn txtbuilder_works() {
        let mut rdata = Vec::new();
        let mut builder = TxtBuilder::new(&mut rdata);
        let cs_a = b"a character-string".try_into().unwrap();
        let cs_b = b"another character-string".try_into().unwrap();
        builder.try_push(cs_a).unwrap();
        builder.try_push(cs_b).unwrap();
        assert_eq!(rdata, b"\x12a character-string\x18another character-string");
    }

    #[test]
    fn txtbuilder_rejects_rdata_overflow() {
        let mut rdata = Vec::new();
        let mut builder = TxtBuilder::new(&mut rdata);
        let character_string: &CharacterString = [0; 255].as_slice().try_into().unwrap();
        for _ in 0..255 {
            builder.try_push(character_string).unwrap();
        }
        assert_eq!(builder.try_push(character_string), Err(RdataTooLongError));
    }
}
