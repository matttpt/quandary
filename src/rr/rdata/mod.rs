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

use super::Type;
use crate::class::Class;
use crate::name::{self, Name};
use crate::util::nibble_to_ascii_hex_digit;

// Implementation helpers.
mod helpers;

// Implementations of RR types.
mod ipv6;
mod opt;
mod srv;
mod std13;
mod tsig;
pub use ipv6::*;
pub use opt::*;
pub use srv::*;
pub use std13::*;
pub use tsig::*;

////////////////////////////////////////////////////////////////////////
// RDATA TYPE                                                         //
////////////////////////////////////////////////////////////////////////

/// A type for record RDATA.
///
/// The RDATA of a record is limited to 65,535 octets. The `Rdata` type
/// is a wrapper over `[u8]` that can only be constructed if the
/// underlying data has a valid length.
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

    /// Determines whether this [`Rdata`] is equal to another, assuming
    /// that they are both of type `rr_type` in class `class`.
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
    pub fn equals(&self, other: &Self, class: Class, rr_type: Type) -> bool {
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => helpers::names_equal(&self.octets, &other.octets),
            Type::A if class == Class::CH => self.equals_as_ch_a(other),
            Type::SOA => self.equals_as_soa(other),
            Type::MINFO => self.equals_as_minfo(other),
            Type::MX => self.equals_as_mx(other),
            Type::SRV if class == Class::IN => self.equals_as_in_srv(other),
            _ => self.octets == other.octets,
        }
    }

    /// Validates an [`Rdata`] for correctness, assuming that it is of
    /// type `rr_type` in class `class`. If the class/type combination
    /// is unknown, then this is a successful no-op.
    pub fn validate(&self, class: Class, rr_type: Type) -> Result<(), ReadRdataError> {
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => helpers::validate_name(&self.octets),
            Type::A if class == Class::IN => self.validate_as_in_a(),
            Type::A if class == Class::CH => self.validate_as_ch_a(),
            Type::SOA => self.validate_as_soa(),
            // For NULL, there is nothing to do!
            Type::WKS if class == Class::IN => self.validate_as_in_wks(),
            Type::HINFO => self.validate_as_hinfo(),
            Type::MINFO => self.validate_as_minfo(),
            Type::MX => self.validate_as_mx(),
            Type::TXT => self.validate_as_txt(),
            Type::AAAA if class == Class::IN => self.validate_as_in_aaaa(),
            Type::SRV if class == Class::IN => self.validate_as_in_srv(),
            Type::OPT => self.validate_as_opt(),
            Type::TSIG => self.validate_as_tsig(),
            _ => Ok(()),
        }
    }

    /// Reads RDATA from a message, validating it while also
    /// decompressing any embedded domain names, if compressed domain
    /// names are allowed for the RR type.
    ///
    /// RDATA of type `rr_type` in class `class` and of length
    /// `rdlength` is read starting from `&message[cursor]`. The
    /// behavior is as follows:
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
        class: Class,
        rr_type: Type,
        message: &[u8],
        cursor: usize,
        rdlength: u16,
    ) -> Result<Cow<Self>, ReadRdataError> {
        type Reader = fn(&[u8], usize, u16) -> Result<Box<Rdata>, ReadRdataError>;
        type Validator = fn(&Rdata) -> Result<(), ReadRdataError>;
        let with_decompression = |reader: Reader| reader(message, cursor, rdlength).map(Cow::Owned);
        let without_decompression = |validator: Validator| {
            helpers::prepare_to_read_rdata(message, cursor, rdlength).and_then(|buf| {
                let rdata = (&buf[cursor..]).try_into().unwrap();
                validator(rdata).and(Ok(Cow::Borrowed(rdata)))
            })
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
            Type::A if class == Class::IN => without_decompression(Self::validate_as_in_a),
            Type::A if class == Class::CH => with_decompression(Self::read_ch_a),
            Type::SOA => with_decompression(Self::read_soa),
            // For NULL, there is no validation to do!
            Type::WKS if class == Class::IN => without_decompression(Self::validate_as_in_wks),
            Type::HINFO => without_decompression(Self::validate_as_hinfo),
            Type::MINFO => with_decompression(Self::read_minfo),
            Type::MX => with_decompression(Self::read_mx),
            Type::TXT => without_decompression(Self::validate_as_txt),
            Type::AAAA if class == Class::IN => without_decompression(Self::validate_as_in_aaaa),
            Type::SRV if class == Class::IN => with_decompression(Self::read_in_srv),
            Type::OPT => without_decompression(Self::validate_as_opt),
            Type::TSIG => without_decompression(Self::validate_as_tsig),
            _ => without_decompression(|_| Ok(())),
        }
    }

    /// Returns an iterator over this `Rdata`'s [`Component`]s, assuming
    /// that it is of type `rr_type` in class `class`.
    pub fn components(&self, class: Class, rr_type: Type) -> Components {
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => Components::for_single_compressible_name(self.octets()),
            Type::A if class == Class::CH => self.components_as_ch_a(),
            Type::SOA => self.components_as_soa(),
            Type::MINFO => self.components_as_minfo(),
            Type::MX => self.components_as_mx(),
            Type::SRV if class == Class::IN => self.components_as_in_srv(),
            _ => Components::for_nameless(self.octets()),
        }
    }

    /// Returns whether the [`Rdata`] is empty.
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// Returns the length of the [`Rdata`].
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Returns the underlying octet slice.
    pub fn octets(&self) -> &[u8] {
        &self.octets
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

impl AsRef<[u8]> for Rdata {
    fn as_ref(&self) -> &[u8] {
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

impl Clone for Box<Rdata> {
    fn clone(&self) -> Self {
        self.as_ref().to_owned()
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
            for octet in self.octets.iter() {
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
// COMPONENTS                                                         //
////////////////////////////////////////////////////////////////////////

/// A component of an [`Rdata`] classified for DNS compression.
///
/// For DNS compression, it is useful to break RDATA into three types of
/// components:
///
/// 1. embedded domain names that may be compressed per [RFC 3597 § 4],
/// 2. embedded domain names that may *not* be compressed per
///    [RFC 3597 § 4], and
/// 3. all other data.
///
/// The [`Components`] iterator, produced by [`Rdata::components`], can
/// be used to iterate the [`Component`]s of an [`Rdata`].
///
/// [RFC 3597 § 4]: https://datatracker.ietf.org/doc/html/rfc3597#section-4
pub enum Component<'a> {
    CompressibleName(Box<Name>),
    UncompressibleName(Box<Name>),
    Other(&'a [u8]),
}

/// Specifies (for [`Components::next`]) how to parse the next
/// [`Component`] of an [`Rdata`].
#[derive(Copy, Clone, Debug)]
enum ComponentType {
    CompressibleName,
    UncompressibleName,
    FixedLen(usize),
}

/// An iterator over the [`Component`]s of an [`Rdata`]. See
/// [`Rdata::components`].
pub struct Components<'a> {
    types: &'static [ComponentType],
    rdata: &'a [u8],
}

impl<'a> Components<'a> {
    /// Creates a `Components` iterator for RDATA that is a single,
    /// compressible domain name (e.g. CNAME or NS RDATA).
    fn for_single_compressible_name(rdata: &'a [u8]) -> Self {
        Self {
            types: &[ComponentType::CompressibleName],
            rdata,
        }
    }

    /// Creates a `Components` iterator for RDATA that does not embed
    /// any domain names.
    fn for_nameless(rdata: &'a [u8]) -> Self {
        Self { types: &[], rdata }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Result<Component<'a>, ReadRdataError>;

    fn next(&mut self) -> Option<Result<Component<'a>, ReadRdataError>> {
        if let Some((next_type, remaining_types)) = self.types.split_first() {
            let (component, remaining_rdata) = match *next_type {
                ComponentType::CompressibleName => match build_name_component(self.rdata, true) {
                    Ok(res) => res,
                    Err(e) => return Some(Err(e)),
                },
                ComponentType::UncompressibleName => {
                    match build_name_component(self.rdata, false) {
                        Ok(res) => res,
                        Err(e) => return Some(Err(e)),
                    }
                }
                ComponentType::FixedLen(len) => {
                    let fixed = match self.rdata.get(0..len) {
                        Some(fixed) => fixed,
                        None => return Some(Err(ReadRdataError::UnexpectedEom)),
                    };
                    let remaining = &self.rdata[len..];
                    (Component::Other(fixed), remaining)
                }
            };
            self.types = remaining_types;
            self.rdata = remaining_rdata;
            Some(Ok(component))
        } else if self.rdata.is_empty() {
            None
        } else {
            let component = Component::Other(self.rdata);
            self.rdata = &[];
            Some(Ok(component))
        }
    }
}

/// A helper to build one of the two domain name [`Component`] variants
/// from RDATA.
fn build_name_component(
    rdata: &[u8],
    compressible: bool,
) -> Result<(Component<'static>, &[u8]), ReadRdataError> {
    let (name, len) = Name::try_from_uncompressed(rdata)?;
    let component = if compressible {
        Component::CompressibleName(name)
    } else {
        Component::UncompressibleName(name)
    };
    let remaining = &rdata[len..];
    Ok((component, remaining))
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

/// An error signaling that RDATA could not be
/// read/decompressed/validated.
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
        assert!(matches!(
            <&Rdata>::try_from(&too_long[..]),
            Err(RdataTooLongError),
        ));
    }

    #[test]
    fn read_checks_if_message_is_long_enough() {
        // For RR types that require decompression and therefore have
        // type-specific Rdata::read_* functions, the check occurs at
        // the beginning of those functions; for other RR types, it
        // occurs in Rdata::read itself. We test every possible RR type
        // in class IN, plus the class-specific RR types that we support
        // outside class IN, to ensure correct behavior. (NOTE: whenever
        // support for a new class-specific type outside IN is added,
        // this test should be updated.)
        let too_short = [0; 4];
        for i in 0..=u16::MAX {
            assert!(matches!(
                Rdata::read(Class::IN, Type::from(i), &too_short[..], 2, 4),
                Err(ReadRdataError::UnexpectedEom),
            ));
        }
        assert!(matches!(
            Rdata::read(Class::CH, Type::A, &too_short, 2, 4),
            Err(ReadRdataError::UnexpectedEom),
        ));
    }
}
