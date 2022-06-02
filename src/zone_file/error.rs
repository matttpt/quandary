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

//! Error types for zone file parsing.
//!
//! In order to maintain consistency in error messages (and to avoid
//! unnecessary allocation of strings), all syntax errors are recorded
//! with the an [`ErrorKind`] value that can be used by calling code to
//! get an appropriate error message.

use std::fmt;
use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::str::Utf8Error;

use super::Position;
use crate::name;

////////////////////////////////////////////////////////////////////////
// ERROR STRUCTURE                                                    //
////////////////////////////////////////////////////////////////////////

/// Represents errors that may occur during zone file parsing.
#[derive(Debug)]
pub enum Error {
    /// I/O errors encountered while reading a zone file.
    Io(io::Error),

    /// Syntax errors.
    Syntax(ErrorDetails),
}

impl Error {
    /// Constructs a new [`Error`] of the [`Syntax`](`Error::Syntax`)
    /// variant with provided information.
    pub(super) fn new(position: Position, kind: ErrorKind) -> Self {
        Self::Syntax(ErrorDetails { position, kind })
    }
}

impl From<io::Error> for Error {
    fn from(io_error: io::Error) -> Self {
        Self::Io(io_error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(io_error) => write!(f, "I/O error: {}", io_error),
            Self::Syntax(details) => details.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// A result type for zone file parsing.
pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////
// SYNTAX ERROR DETAILS                                               //
////////////////////////////////////////////////////////////////////////

/// Provides information about the position and kind of zone file syntax
/// errors.
#[derive(Debug)]
pub struct ErrorDetails {
    pub(super) position: Position,
    pub(super) kind: ErrorKind,
}

impl ErrorDetails {
    /// Returns the line in the file at which the error occurred.
    pub fn line(&self) -> usize {
        self.position.line
    }

    /// Returns the column in the file at which the error occurred.
    pub fn column(&self) -> usize {
        self.position.column
    }

    /// Returns the kind of syntax error that occurred.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for ErrorDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} at line {} column {}",
            self.kind, self.position.line, self.position.column,
        )
    }
}

////////////////////////////////////////////////////////////////////////
// SYNTAX ERROR KINDS                                                 //
////////////////////////////////////////////////////////////////////////

/// Kinds of zone file syntax errors.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    AtWhenOriginNotSet,
    BadUtf8(Utf8Error),
    CharacterStringTooLong,
    EmptyOwnerWithNoPrevious,
    EofBeforeCloseParen,
    EofInEscape,
    EofInQuotedCharacterString,
    EscapeNeedsThreeDigits,
    EscapeValueOutOfRange,
    ExpectedBackslashHash,
    ExpectedCharacterString,
    ExpectedCharacterStringOrBh,
    ExpectedClassOrType,
    ExpectedEol,
    ExpectedHexRdata,
    ExpectedIpProto,
    ExpectedIpv4OrBh,
    ExpectedIpv6OrBh,
    ExpectedName,
    ExpectedNameOrBh,
    ExpectedRdataLen,
    ExpectedTtl,
    ExpectedTtlClassOrType,
    ExpectedTtlOrType,
    ExpectedType,
    ExpectedU16,
    ExpectedU16OrBh,
    ExpectedU32,
    FieldTooLong,
    InvalidClass(&'static str),
    InvalidHexDigit,
    InvalidInt(ParseIntError),
    InvalidIpv4(AddrParseError),
    InvalidIpv6(AddrParseError),
    InvalidLabel(name::Error),
    InvalidName(name::Error),
    InvalidRdataForType,
    InvalidRdataLen(ParseIntError),
    InvalidTtl(ParseIntError),
    InvalidType(&'static str),
    NestedParens,
    NullNotAllowed,
    OmittedClassWithNoPrevious,
    OmittedTtlWithNoDefaultOrPrevious,
    OptNotAllowed,
    PqdnWhenOriginNotSet,
    TxtTooLong,
    UnexpectedEndOfHexRdata,
    UnknownDirective,
    UnmatchedCloseParen,
    WksTooLong,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::AtWhenOriginNotSet => f.write_str("cannot use @ when no origin is set"),
            Self::BadUtf8(utf8_err) => utf8_err.fmt(f),
            Self::CharacterStringTooLong => f.write_str("<character-string> is too long"),
            Self::EmptyOwnerWithNoPrevious => {
                f.write_str("the owner cannot be empty when no previous owner is available")
            }
            Self::EofBeforeCloseParen => {
                f.write_str("reached end of file before close parenthesis")
            }
            Self::EofInEscape => f.write_str("reached end of file in escape sequence"),
            Self::EofInQuotedCharacterString => {
                f.write_str("reached end of file in quoted <character-string>")
            }
            Self::EscapeNeedsThreeDigits => {
                f.write_str("invalid escape sequence: expected three decimal digits")
            }
            Self::EscapeValueOutOfRange => {
                f.write_str("invalid escape sequence: escaped octet value is out of range")
            }
            Self::ExpectedBackslashHash => f.write_str("expected \\#"),
            Self::ExpectedCharacterString => f.write_str("expected a <character-string>"),
            Self::ExpectedCharacterStringOrBh => {
                f.write_str("expected a <character-string> or \\#")
            }
            Self::ExpectedClassOrType => f.write_str("expected a class or RR type"),
            Self::ExpectedEol => f.write_str("expected the end of the line"),
            Self::ExpectedHexRdata => f.write_str("expected hexadecimal RDATA"),
            Self::ExpectedIpProto => {
                f.write_str("expected an IP protocol (TCP, UDP, or an unsigned 8-bit integer)")
            }
            Self::ExpectedIpv4OrBh => f.write_str("expected an IPv4 address or \\#"),
            Self::ExpectedIpv6OrBh => f.write_str("expected an IPv6 address or \\#"),
            Self::ExpectedName => f.write_str("expected a domain name"),
            Self::ExpectedNameOrBh => f.write_str("expected a domain name or \\#"),
            Self::ExpectedRdataLen => f.write_str("expected RDATA length"),
            Self::ExpectedTtl => f.write_str("expected a TTL"),
            Self::ExpectedTtlClassOrType => f.write_str("expected a TTL, class, or RR type"),
            Self::ExpectedTtlOrType => f.write_str("expected a TTL or RR type"),
            Self::ExpectedType => f.write_str("expected an RR type"),
            Self::ExpectedU16 => f.write_str("expected an unsigned 16-bit integer"),
            Self::ExpectedU16OrBh => f.write_str("expected an unsigned 16-bit integer or \\#"),
            Self::ExpectedU32 => f.write_str("expected an unsigned 32-bit integer"),
            Self::FieldTooLong => f.write_str("field is too long to parse"),
            Self::InvalidClass(class_err) => class_err.fmt(f),
            Self::InvalidHexDigit => f.write_str("invalid hexadecimal digit"),
            Self::InvalidInt(ref int_err) => int_err.fmt(f),
            Self::InvalidIpv4(ref addr_err) => addr_err.fmt(f),
            Self::InvalidIpv6(ref addr_err) => addr_err.fmt(f),
            Self::InvalidLabel(name_err) => write!(f, "invalid label: {}", name_err),
            Self::InvalidName(name_err) => write!(f, "invalid name: {}", name_err),
            Self::InvalidRdataForType => f.write_str("invalid RDATA for the RR type"),
            Self::InvalidRdataLen(ref int_err) => write!(f, "invalid RDATA length: {}", int_err),
            Self::InvalidTtl(ref int_err) => write!(f, "invalid TTL: {}", int_err),
            Self::InvalidType(type_err) => type_err.fmt(f),
            Self::NestedParens => f.write_str("nested parentheses"),
            Self::NullNotAllowed => f.write_str("NULL records are not allowed in zone files"),
            Self::OmittedClassWithNoPrevious => {
                f.write_str("class omitted with no previous class available")
            }
            Self::OmittedTtlWithNoDefaultOrPrevious => {
                f.write_str("TTL omitted with no default TTL or previous TTL available")
            }
            Self::OptNotAllowed => f.write_str("OPT records are not allowed in zone files"),
            Self::PqdnWhenOriginNotSet => {
                f.write_str("cannot use a partially qualified domain name when no origin is set")
            }
            Self::TxtTooLong => f.write_str("TXT record is too long"),
            Self::UnexpectedEndOfHexRdata => f.write_str("unexpected end of hexadecimal RDATA"),
            Self::UnknownDirective => f.write_str("unknown directive"),
            Self::UnmatchedCloseParen => f.write_str("unmatched close parenthesis"),
            Self::WksTooLong => f.write_str("WKS record is too long"),
        }
    }
}
