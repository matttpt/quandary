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

//! Parsing of resource records.

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Error, ErrorKind, FieldOrEol, Line, LineContent, ParsedRr, Parser, Position, Result};
use crate::class::Class;
use crate::name::Name;
use crate::rr::rdata::{Rdata, RdataTooLongError, TxtBuilder};
use crate::rr::{Ttl, Type};
use crate::util::ascii_hex_digit_to_nibble;

impl<S: Read> Parser<S> {
    ////////////////////////////////////////////////////////////////////
    // PARSING OF RESOURCE RECORDS (OR EMPTY LINES)                   //
    ////////////////////////////////////////////////////////////////////

    /// Parses a resource record or an empty line.
    pub(super) fn parse_record_or_empty(&mut self) -> Result<Option<Line>> {
        let start_of_line = self.reader.position();
        let leading_whitespace = self.reader.skip_whitespace()?;
        if self.reader.skip_to_next_field_or_through_eol()? == FieldOrEol::Eol {
            // It was an empty line.
            return Ok(None);
        }

        // In zone files, leading whitespace is significant. If it
        // exists, then the owner for the record on this line is the
        // same as the owner for the previous record.
        let owner = if leading_whitespace {
            if let Some(ref previous_owner) = self.context.previous_owner {
                previous_owner.clone()
            } else {
                return Err(Error::new(
                    start_of_line,
                    ErrorKind::EmptyOwnerWithNoPrevious,
                ));
            }
        } else {
            self.parse_name()?
        };

        // The next fields are the TTL and class. They may appear in
        // either order, and furthermore the TTL may be omitted.
        self.reader
            .skip_to_next_field(ErrorKind::ExpectedTtlClassOrType)?;
        let (ttl, class) = self.parse_ttl_and_class()?;

        // The type field is next.
        self.reader.skip_to_next_field(ErrorKind::ExpectedType)?;
        let rr_type = self.parse_type()?;

        // The RDATA completes the record. What we expect to see next
        // depends on the RR's class and type, so parse_rdata performs
        // the skip to the next field itself while providing the right
        // error message for the type. This call also consumes the end
        // of the line.
        let rdata = self.parse_rdata(class, rr_type)?;

        // Update the context for the next record parsed.
        self.context.previous_owner = Some(owner.clone());
        self.context.previous_ttl = Some(ttl);
        self.context.previous_class = Some(class);

        Ok(Some(Line {
            number: start_of_line.line,
            content: LineContent::Record(ParsedRr {
                owner,
                ttl,
                class,
                rr_type,
                rdata,
            }),
        }))
    }

    ////////////////////////////////////////////////////////////////////
    // RESOURCE RECORD PARSING HELPERS                                //
    ////////////////////////////////////////////////////////////////////

    /// Parses the TTL and CLASS fields of a record. This is tricky
    /// because we may see TTL then CLASS, CLASS then TTL, only one of
    /// the two, or neither. When omitted, the CLASS defaults to the
    /// previous record's CLASS. The TTL defaults to the one specified
    /// by the most recent `$TTL` directive ([RFC 2308 § 4]), or if
    /// there is none, then the previous record's TTL.
    ///
    /// [RFC 2308 § 4]: https://datatracker.ietf.org/doc/html/rfc2308
    fn parse_ttl_and_class(&mut self) -> Result<(Ttl, Class)> {
        // As noted in RFC 1035 § 5.1, the possible TTL, class, and
        // subsequent type fields are disjoint, so the parse is unique.
        // We just need to try the possibilities.
        //
        // Here, we rely on the fact that the Reader::read_field method
        // (of which parse_ttl and parse_class are simple wrappers) does
        // not consume data or leave an invalid state on parse failure.
        // Thus we can simply try again with a different data type.
        if let Ok(ttl) = self.parse_ttl() {
            self.reader
                .skip_to_next_field(ErrorKind::ExpectedClassOrType)?;
            if let Ok(class) = self.parse_class() {
                Ok((ttl, class))
            } else if let Some(class) = self.context.previous_class {
                Ok((ttl, class))
            } else {
                Err(Error::new(
                    self.reader.position(),
                    ErrorKind::OmittedClassWithNoPrevious,
                ))
            }
        } else if let Ok(class) = self.parse_class() {
            self.reader
                .skip_to_next_field(ErrorKind::ExpectedTtlOrType)?;
            if let Ok(ttl) = self.parse_ttl() {
                Ok((ttl, class))
            } else if let Some(ttl) = self.default_or_previous_ttl() {
                Ok((ttl, class))
            } else {
                Err(Error::new(
                    self.reader.position(),
                    ErrorKind::OmittedTtlWithNoDefaultOrPrevious,
                ))
            }
        } else {
            match (self.default_or_previous_ttl(), self.context.previous_class) {
                (Some(ttl), Some(class)) => Ok((ttl, class)),
                (Some(_), _) => Err(Error::new(
                    self.reader.position(),
                    ErrorKind::OmittedClassWithNoPrevious,
                )),
                _ => Err(Error::new(
                    self.reader.position(),
                    ErrorKind::OmittedTtlWithNoDefaultOrPrevious,
                )),
            }
        }
    }

    /// A simple wrapper to parse a [`Ttl`] with
    /// [`super::Reader::read_field`].
    fn parse_ttl(&mut self) -> Result<Ttl> {
        self.reader
            .read_field::<u32, _>(ErrorKind::InvalidTtl)
            .map(Ttl::from)
    }

    /// A simple wrapper to parse a [`Class`] with
    /// [`super::Reader::read_field`].
    fn parse_class(&mut self) -> Result<Class> {
        self.reader.read_field(ErrorKind::InvalidClass)
    }

    /// Parses a [`Type`]. If the parsed type is not allowed in zone
    /// files (e.g. NULL and OPT), then an error is raised.
    fn parse_type(&mut self) -> Result<Type> {
        let position = self.reader.position();
        let rr_type = self.reader.read_field(ErrorKind::InvalidType)?;
        match rr_type {
            Type::NULL => Err(Error::new(position, ErrorKind::NullNotAllowed)),
            Type::OPT => Err(Error::new(position, ErrorKind::OptNotAllowed)),
            Type::TSIG => Err(Error::new(position, ErrorKind::TsigNotAllowed)),
            _ => Ok(rr_type),
        }
    }

    /// Returns the TTL to use if the TTL field is omitted. (See
    /// [`Parser::parse_ttl_and_class`].)
    fn default_or_previous_ttl(&self) -> Option<Ttl> {
        self.context.default_ttl.or(self.context.previous_ttl)
    }

    ////////////////////////////////////////////////////////////////////
    // RDATA PARSING                                                  //
    ////////////////////////////////////////////////////////////////////

    // RDATA parsing has some complications, since each RR type has a
    // different format, and furthermore RFC 3597 § 5 allows RDATA for
    /// *any* type to be expressed using the raw format (starting with
    // \#) intended for entering RDATA of unknown types. When RDATA is
    // entered this way for a known type, we should check it for
    // validity.
    //
    // The parse_*_rdata methods parse according to the various
    // type-dependent formats into raw RDATA octets or, if \# is
    // detected, use parse_unknown_rdata to parse the raw format and
    // then validate the user-supplied raw octets. The parse_rdata
    // method dispatches the appropriate parse_*_rdata method based on
    // the provided type, or, if the type is unknown, requires the use
    // of the \# format.
    //
    // In this zone file parsing code, the general practice is for
    // calling code to advance the Reader to the next field *before*
    // calling a method to parse a feature. However, for the sake of
    // good error messages, this practice is *reversed* here for the
    // parse_rdata and parse_*_rdata methods. The appropriate error
    // message when the file unexpectedly ends ("expected ...") depends
    // on the type of the record, so just this once it makes sense to
    // include the skipping in the callee.
    //
    // Note also that the RDATA parsing methods also consume the next
    // line ending. This makes sense because some RDATA formats (such as
    // for TXT records) do not have a fixed number of fields.

    /// Parses RDATA for a record of type `rr_type` in class `class`.
    /// Note that unlike most of the zone file parsing methods, this
    /// method does *not* require the caller to skip to the next field
    /// before use. This is because the error message generation is
    /// handled in the callee, since the message depends on `rr_type`
    /// and `class`. Furthermore, this method expects and consumes a
    /// line ending after the RDATA.
    fn parse_rdata(&mut self, class: Class, rr_type: Type) -> Result<Box<Rdata>> {
        match rr_type {
            Type::NS
            | Type::MD
            | Type::MF
            | Type::CNAME
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::PTR => self.parse_name_rdata(),
            Type::A if class == Class::IN => self.parse_in_a_rdata(),
            Type::A if class == Class::CH => self.parse_ch_a_rdata(),
            Type::SOA => self.parse_soa_rdata(),
            Type::WKS if class == Class::IN => self.parse_in_wks_rdata(),
            Type::HINFO => self.parse_hinfo_rdata(),
            Type::MINFO => self.parse_minfo_rdata(),
            Type::MX => self.parse_mx_rdata(),
            Type::TXT => self.parse_txt_rdata(),
            Type::AAAA if class == Class::IN => self.parse_in_aaaa_rdata(),
            Type::SRV if class == Class::IN => self.parse_in_srv_rdata(),
            _ => {
                // Since we don't recognize the class/type combination,
                // require the \# format.
                if !self.check_backslash_hash(ErrorKind::ExpectedBackslashHash)? {
                    return Err(Error::new(
                        self.reader.position(),
                        ErrorKind::ExpectedBackslashHash,
                    ));
                }
                self.parse_unknown_rdata()
            }
        }
    }

    /// A helper for beginning to parse a record's RDATA. It advances
    /// the `Reader` to the next field (producing an error based on
    /// `expected`) if there is no such field. It then returns `true` if
    /// the next field is the \# sequence indicating that the RDATA is
    /// given in raw form, and `false` otherwise.
    fn check_backslash_hash(&mut self, expected: ErrorKind) -> Result<bool> {
        self.reader.skip_to_next_field(expected)?;
        self.reader.expect_field(b"\\#").map_err(Into::into)
    }

    /// Parses RDATA for records consisting of a single domain name.
    fn parse_name_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedNameOrBh)? {
            self.parse_unknown_rdata_with_validation(|rdata| {
                Name::validate_uncompressed_all(rdata.octets())
            })
        } else {
            let name = self.parse_name()?;
            self.reader.expect_eol()?;
            Ok(<&Rdata>::try_from(name.wire_repr()).unwrap().to_owned())
        }
    }

    /// Parses RDATA for Internet A records.
    fn parse_in_a_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedIpv4OrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_in_a)
        } else {
            let ipv4: Ipv4Addr = self.reader.read_field(ErrorKind::InvalidIpv4)?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_in_a(ipv4))
        }
    }

    /// Parses RDATA for Chaosnet A records.
    fn parse_ch_a_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedNameOrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_ch_a)
        } else {
            let lan = self.parse_name()?;
            self.reader
                .skip_to_next_field(ErrorKind::ExpectedChaosnetAddr)?;
            let address = self.parse_chaosnet_address()?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_ch_a(&lan, address))
        }
    }

    /// Parses a 16-bit Chaosnet address, expressed in octal.
    fn parse_chaosnet_address(&mut self) -> Result<u16> {
        let mut address: u16 = 0;
        let start_position = self.reader.position();
        while let Some(octet) = self.reader.read_field_octet()? {
            if matches!(octet, b'0'..=b'7') {
                address = address
                    .checked_mul(8)
                    .ok_or_else(|| Error::new(start_position, ErrorKind::InvalidChaosnetAddr))?;
                address += (octet - b'0') as u16;
            } else {
                return Err(Error::new(start_position, ErrorKind::InvalidChaosnetAddr));
            }
        }
        Ok(address)
    }

    /// Parses RDATA for SOA records.
    fn parse_soa_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedNameOrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_soa)
        } else {
            let mname = self.parse_name()?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
            let rname = self.parse_name()?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU32)?;
            let serial = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU32)?;
            let refresh = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU32)?;
            let retry = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU32)?;
            let expire = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU32)?;
            let minimum = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_soa(
                &mname, &rname, serial, refresh, retry, expire, minimum,
            ))
        }
    }

    /// Parses RDATA for WKS records.
    ///
    /// Note that mneumonics for port numbers are not supported, and the
    /// only support mneumonics for IP protocols are `TCP` and `UDP`.
    fn parse_in_wks_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedIpv4OrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_in_wks)
        } else {
            let start_position = self.reader.position();

            let address: Ipv4Addr = self.reader.read_field(ErrorKind::InvalidIpv4)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedIpProto)?;
            let protocol = if self.reader.expect_field_case_insensitive(b"TCP")? {
                6
            } else if self.reader.expect_field_case_insensitive(b"UDP")? {
                17
            } else {
                self.reader.read_field(ErrorKind::InvalidInt)?
            };

            let mut ports = Vec::new();
            while self.reader.skip_to_next_field_or_through_eol()? == FieldOrEol::Field {
                // Since there are only 65536 ports for TCP and UDP, we
                // should never need to have more of them.
                if ports.len() >= u16::MAX as usize {
                    return Err(Error::new(start_position, ErrorKind::WksTooLong));
                }

                let port = self.reader.read_field(ErrorKind::InvalidInt)?;
                ports.push(port);
            }

            Ok(Rdata::new_in_wks(address, protocol, &ports))
        }
    }

    /// Parses RDATA for HINFO records.
    fn parse_hinfo_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedCharacterStringOrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_hinfo)
        } else {
            let cpu = self.parse_character_string()?;
            self.reader
                .skip_to_next_field(ErrorKind::ExpectedCharacterString)?;
            let os = self.parse_character_string()?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_hinfo(&cpu, &os))
        }
    }

    /// Parses RDATA for MINFO records.
    fn parse_minfo_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedNameOrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_minfo)
        } else {
            let rmailbx = self.parse_name()?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
            let emailbx = self.parse_name()?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_minfo(&rmailbx, &emailbx))
        }
    }

    /// Parses RDATA for MX records.
    fn parse_mx_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedU16OrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_mx)
        } else {
            let preference = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
            let exchange = self.parse_name()?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_mx(preference, &exchange))
        }
    }

    /// Parses RDATA for TXT records.
    fn parse_txt_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedCharacterStringOrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_txt)
        } else {
            let mut rdata = Vec::new();
            let mut builder = TxtBuilder::new(&mut rdata);
            let start_position = self.reader.position();
            loop {
                let character_string = self.parse_character_string()?;
                match builder.try_push(&character_string) {
                    Ok(()) => (),
                    Err(RdataTooLongError) => {
                        return Err(Error::new(start_position, ErrorKind::TxtTooLong))
                    }
                }
                if self.reader.skip_to_next_field_or_through_eol()? == FieldOrEol::Eol {
                    break;
                }
            }
            Ok(rdata.try_into().unwrap())
        }
    }

    /// Parses RDATA for AAAA records.
    fn parse_in_aaaa_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedIpv6OrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_in_aaaa)
        } else {
            let ipv6: Ipv6Addr = self.reader.read_field(ErrorKind::InvalidIpv6)?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_in_aaaa(ipv6))
        }
    }

    /// Parses RDATA for SRV records.
    fn parse_in_srv_rdata(&mut self) -> Result<Box<Rdata>> {
        if self.check_backslash_hash(ErrorKind::ExpectedU16OrBh)? {
            self.parse_unknown_rdata_with_validation(Rdata::validate_as_in_srv)
        } else {
            let priority = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU16)?;
            let weight = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedU16)?;
            let port = self.reader.read_field(ErrorKind::InvalidInt)?;
            self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
            let target = self.parse_name()?;
            self.reader.expect_eol()?;
            Ok(Rdata::new_in_srv(priority, weight, port, &target))
        }
    }

    /// Parses RDATA using the \# format. This expects that the caller
    /// has already consumed the \# marker and starts by skipping to the
    /// next field in the format (the RDATA length).
    fn parse_unknown_rdata(&mut self) -> Result<Box<Rdata>> {
        self.parse_unknown_rdata_impl().map(|(_, v)| v)
    }

    /// Like [`Parser::parse_unknown_rdata`], except that the RDATA is
    /// additionally validated with `validator` once it is parsed. If
    /// validation fails, an error of kind
    /// [`ErrorKind::InvalidRdataForType`] is returned.
    fn parse_unknown_rdata_with_validation<V, R, E>(&mut self, validator: V) -> Result<Box<Rdata>>
    where
        V: FnOnce(&Rdata) -> std::result::Result<R, E>,
    {
        let (hex_digits_position, rdata) = self.parse_unknown_rdata_impl()?;
        if validator(rdata.as_ref()).is_ok() {
            Ok(rdata)
        } else {
            Err(Error::new(
                hex_digits_position,
                ErrorKind::InvalidRdataForType,
            ))
        }
    }

    /// The implementation of unknown RDATA parsing. In addition to the
    /// RDATA parsed, this returns the start position of the hexadecimal
    /// digits (or the position immediately after the RDATA length
    /// field) for error reporting in
    /// [`Parser::parse_unknown_rdata_with_validation`].
    fn parse_unknown_rdata_impl(&mut self) -> Result<(Position, Box<Rdata>)> {
        self.reader
            .skip_to_next_field(ErrorKind::ExpectedRdataLen)?;
        let len = self
            .reader
            .read_field::<u16, _>(ErrorKind::InvalidRdataLen)?;
        let result = if len == 0 {
            (self.reader.position(), Rdata::empty().to_owned())
        } else {
            self.reader
                .skip_to_next_field(ErrorKind::ExpectedHexRdata)?;
            let hex_digits_position = self.reader.position();
            let rdata = self.parse_unknown_rdata_hex_digits(len)?;
            (hex_digits_position, rdata)
        };
        self.reader.expect_eol()?;
        Ok(result)
    }

    /// Parses a string of hexadecimal digits for a total of `len`
    /// octets.
    fn parse_unknown_rdata_hex_digits(&mut self, len: u16) -> Result<Box<Rdata>> {
        let len = len as usize;
        let mut rdata = Vec::with_capacity(len);
        while rdata.len() < len {
            let high_nibble = self.parse_ascii_hex_digit()?;
            let low_nibble = self.parse_ascii_hex_digit()?;
            rdata.push((high_nibble << 4) | low_nibble);
        }
        Ok(rdata.try_into().unwrap())
    }

    /// Parses a single ASCII hexadecimal digit.
    fn parse_ascii_hex_digit(&mut self) -> Result<u8> {
        match self.reader.read_field_octet()? {
            Some(digit) => match ascii_hex_digit_to_nibble(digit) {
                Some(n) => Ok(n),
                None => Err(Error::new(
                    self.reader.position(),
                    ErrorKind::InvalidHexDigit,
                )),
            },
            None => Err(Error::new(
                self.reader.position(),
                ErrorKind::UnexpectedEndOfHexRdata,
            )),
        }
    }
}
