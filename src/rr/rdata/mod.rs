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

//! Implementation of the [`Rdata`] type and DNS RDATA processing.

use std::borrow::Cow;
use std::fmt::{self, Write};
use std::ops::Deref;

use super::Type;
use crate::name;
use crate::util::nibble_to_ascii_hex_digit;

// Implementation helpers.
mod helpers;

// Implementations of RR types.
mod ipv6;
mod opt;
mod srv;
mod std13;
pub use ipv6::*;
pub use opt::*;
pub use srv::*;
pub use std13::*;

////////////////////////////////////////////////////////////////////////
// RDATA TYPE                                                         //
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
    pub(super) fn from_unchecked(octets: &[u8]) -> &Self {
        unsafe { &*(octets as *const [u8] as *const Self) }
    }

    /// Returns an empty `&Rdata`.
    pub fn empty() -> &'static Self {
        Self::from_unchecked(&[])
    }

    /// Compares this [`Rdata`] to another, assuming that they are both
    /// of type `rr_type`.
    ///
    /// [RFC 3597 § 6] specifies that RRs of unknown type are equal when
    /// their RDATA is bitwise equal, and that new RR types should not
    /// have type-specific comparison rules. This means that embedded
    /// domain names are henceforth compared in a case-sensitive manner!
    /// Therefore, only types that (1) predate the RFC and (2) embed
    /// domain names need to have special comparison logic. This method
    /// carries out the special comparison logic for these types, and
    /// performs bitwise comparison otherwise.
    ///
    /// If, in the process of comparing domain names case-insensitively,
    /// one of the [`Rdata`]s is found to be invalid, this falls back to
    /// a bitwise comparison of the entire [`Rdata`]s.
    ///
    /// *Warning:* OPT pseudo-record RDATA will be compared bitwise, not
    /// semantically. Since these do not belong in DNS zone data and
    /// may appear only once in a DNS message, there is probably not a
    /// use case for comparing them at all; thus this method sticks with
    /// the default bitwise comparison.
    ///
    /// [RFC 3597 § 6]: https://datatracker.ietf.org/doc/html/rfc3597#section-6
    pub fn equals(&self, other: &Self, rr_type: Type) -> bool {
        if self.octets().len() != other.octets().len() {
            // Since equal embedded domain names are always the same
            // length (even if they contain octets of differing ASCII
            // case), the RDATAs can't be equal if they have differing
            // lengths.
            false
        } else {
            match rr_type {
                Type::NS
                | Type::MD
                | Type::MF
                | Type::CNAME
                | Type::MB
                | Type::MG
                | Type::MR
                | Type::PTR => helpers::names_equal(self, other),
                Type::SOA => soas_equal(self, other),
                Type::MINFO => minfos_equal(self, other),
                Type::MX => mxs_equal(self, other),
                Type::SRV => srvs_equal(self, other),
                _ => self.octets() == other.octets(),
            }
        }
    }

    /// Validates an [`Rdata`] for correctness, assuming that it is of
    /// type `rr_type`. If the RR type is unknown, this is a successful
    /// no-op.
    pub fn validate(&self, rr_type: Type) -> Result<(), ReadRdataError> {
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => helpers::validate_name(self),
            Type::A => validate_a(self),
            Type::SOA => validate_soa(self),
            // For NULL, there is nothing to do!
            Type::WKS => validate_wks(self),
            Type::HINFO => validate_hinfo(self),
            Type::MINFO => validate_minfo(self),
            Type::MX => validate_mx(self),
            Type::TXT => validate_txt(self),
            Type::AAAA => validate_aaaa(self),
            Type::SRV => validate_srv(self),
            Type::OPT => validate_opt(self),
            _ => Ok(()),
        }
    }

    /// Reads RDATA from a message, validating it while also
    /// decompressing any embedded domain names, if compressed domain
    /// names are allowed for the RR type.
    ///
    /// RDATA of type `rr_type` and length `rdlength` is read starting
    /// from `&message[cursor]`. The behavior is as follows:
    ///
    /// * For recognized RR types that may contain embedded compressed
    ///   domain names, any such domain names are decompressed and the
    ///   RDATA is checked for overall validity. A new buffer for the
    ///   uncompressed RDATA is allocated.
    /// * For recognized RR types that do not contain embedded
    ///   compressed domain names, only validation is performed. A
    ///   reference to the existing buffer is returned.
    /// * For unrecognized RR types, no validation is performed and a
    ///   reference to the existing buffer is returned.
    ///
    /// Per [RFC 3597 § 4], only RDATA of types defined by [RFC 1035]
    /// may contain compressed names, and several more should be subject
    /// to decompression on the receiving end to maintain compatibility
    /// with older software. This function follows [RFC 3597 § 4]'s
    /// prescriptions, with the exception that RP, AFSDB, RT, SIG, PX,
    /// NXT, and NAPTR RDATA are not currently recognized and will not
    /// be subject to decompression. (This is a TODO item.)
    ///
    /// If the remaining part of the message is not `rdlength` long,
    /// this function will fail with [`ReadRdataError::UnexpectedEom`],
    /// rather than panic. Thus it's okay to call this without
    /// validating `rdlength` first.
    ///
    /// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
    /// [RFC 3597 § 4]: https://datatracker.ietf.org/doc/html/rfc3597#section-4
    pub fn read(
        rr_type: Type,
        message: &[u8],
        cursor: usize,
        rdlength: u16,
    ) -> Result<Cow<Rdata>, ReadRdataError> {
        let end = cursor + rdlength as usize;
        if end > message.len() {
            return Err(ReadRdataError::UnexpectedEom);
        }
        let buf = &message[..end];
        let rdata = (&buf[cursor..]).try_into().unwrap();
        let with_decompression =
            |reader: fn(&[u8], usize) -> Result<Box<Rdata>, ReadRdataError>| {
                reader(buf, cursor).map(Cow::Owned)
            };
        let without_decompression = |validator: fn(&Rdata) -> Result<(), ReadRdataError>| {
            validator(rdata).and(Ok(Cow::Borrowed(rdata)))
        };
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => with_decompression(helpers::read_name_rdata),
            Type::A => without_decompression(validate_a),
            Type::SOA => with_decompression(read_soa),
            // For NULL, there is no validation to do!
            Type::WKS => without_decompression(validate_wks),
            Type::HINFO => without_decompression(validate_hinfo),
            Type::MINFO => with_decompression(read_minfo),
            Type::MX => with_decompression(read_mx),
            Type::TXT => without_decompression(validate_txt),
            Type::AAAA => without_decompression(validate_aaaa),
            Type::SRV => with_decompression(read_srv),
            Type::OPT => without_decompression(validate_opt),
            _ => Ok(Cow::Borrowed(rdata)),
        }
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

impl ToOwned for Rdata {
    type Owned = Box<Self>;

    fn to_owned(&self) -> Self::Owned {
        let boxed_octets: Box<[u8]> = self.octets.into();
        unsafe { Box::from_raw(Box::into_raw(boxed_octets) as *mut Rdata) }
    }
}

impl TryFrom<Vec<u8>> for Box<Rdata> {
    type Error = RdataTooLongError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        if vec.len() > (u16::MAX as usize) {
            Err(RdataTooLongError)
        } else {
            let boxed_octets: Box<[u8]> = vec.into_boxed_slice();
            unsafe { Ok(Box::from_raw(Box::into_raw(boxed_octets) as *mut Rdata)) }
        }
    }
}

impl fmt::Display for Rdata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // We output using the RFC 3597 format for RDATA of unknown
        // type.
        write!(f, "\\# {}", self.len())?;
        if !self.is_empty() {
            f.write_char(' ')?;
            for octet in self.iter() {
                f.write_char(char::from(nibble_to_ascii_hex_digit((octet & 0xf0) >> 4)))?;
                f.write_char(char::from(nibble_to_ascii_hex_digit(octet & 0xf)))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Rdata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error signaling that a `&[u8]` cannot be converted to an `&Rdata`
/// because it is too long.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RdataTooLongError;

impl fmt::Display for RdataTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RDATA is too long")
    }
}

impl std::error::Error for RdataTooLongError {}

/// An error signalling that RDATA could not be read/decompressed/
/// validated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReadRdataError {
    InvalidName(name::Error),
    UnexpectedEom,
    Other,
}

impl fmt::Display for ReadRdataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidName(err) => write!(f, "invalid embedded domain name: {}", err),
            Self::UnexpectedEom => f.write_str("unexpected end of message in RDATA"),
            Self::Other => f.write_str("invalid RDATA"),
        }
    }
}

impl std::error::Error for ReadRdataError {}

impl From<name::Error> for ReadRdataError {
    fn from(err: name::Error) -> Self {
        Self::InvalidName(err)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

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
    fn read_checks_if_message_is_long_enough() {
        let too_short = [0; 4];
        assert_eq!(
            Rdata::read(Type::A, &too_short[..], 2, 4),
            Err(ReadRdataError::UnexpectedEom)
        );
    }
}
