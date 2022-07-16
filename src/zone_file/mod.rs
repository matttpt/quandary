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

//! Parsing of the [RFC 1035 § 5] zone file format.
//!
//! This module provides the [`Parser`] structure, which accepts a
//! stream implementing the [`Read`] trait. It can subsequently be
//! iterated over to read DNS records stored in [RFC 1035 § 5] format.
//! It will also report any `$INCLUDE` directives in the file. To
//! receive only records (treating `$INCLUDE` directives as an error),
//! call [`Parser::records_only`], which converts the [`Parser`] into a
//! [`RecordsOnly`] iterator.
//!
//! Errors (which may be I/O errors or syntax errors) are reported
//! through the [`Error`] type. Iteration ends and parsing cannot be
//! continued after an error is returned.
//!
//! ```
//! use std::io::Cursor;
//! use quandary::rr::Type;
//! use quandary::zone_file::Parser;
//!
//! const ZONE_FILE: &[u8] = br#"
//! $ORIGIN quandary.test.
//! $TTL 86400
//! @   IN SOA ns1 admin (
//!     123     ; SERIAL
//!     3600    ; REFRESH
//!     900     ; RETRY
//!     86400   ; EXPIRE
//!     3600    ; MINIMUM
//! )
//!     IN NS ns1
//! ns1 IN A 127.0.0.1
//!     IN AAAA ::1
//! "#;
//!
//! let mut parser = Parser::new(Cursor::new(ZONE_FILE)).records_only();
//! assert_eq!(parser.next().unwrap().unwrap().rr_type, Type::SOA);
//! assert_eq!(parser.next().unwrap().unwrap().rr_type, Type::NS);
//! assert_eq!(parser.next().unwrap().unwrap().rr_type, Type::A);
//! assert_eq!(parser.next().unwrap().unwrap().rr_type, Type::AAAA);
//! assert!(parser.next().is_none());
//! ```
//!
//! # A note about the implementation
//!
//! As has been [previously noted][NLNet], it is very difficult to write
//! clean lexer for DNS zone files. Some complications include:
//!
//! * It is a line-based format, but parentheses can be used to extend a
//!   record across multiple lines.
//!
//! * Leading whitespace in records is significant, because it signals
//!   that the record's owner is the last explicitly stated owner.
//!
//! * It seems from the RFCs and other DNS implementations that escaping
//!   does not apply everywhere. For instance, escaping can be used in
//!   domain names and in `<character-string>`s, but [RFC 3597 § 5]
//!   introduces a special token `\#`, which is not equivalent to a
//!   "regular" `#`. (Testing other DNS implementations confirms this.)
//!   Furthermore, a lexer cannot ignore escape sequences, since (for
//!   example) an escaped space or tab in a domain name does not end the
//!   token, but an unescaped space or tab does. So a lexer must know
//!   what part of the record it is reading, so that it can properly
//!   handle escaping.
//!
//! * Knowing that context takes some real parsing work. For example,
//!
//!   1. The TTL and class may be (independently) omitted, and when they
//!      both appear, we might see `<TTL> <CLASS>` *or* `<CLASS> <TTL>`.
//!
//!   2. The RDATA (record data) format depends on the record type.
//!
//! In light of these hurdles, this module does not have a clean
//! distinction between lexer/tokenizer and parser. Instead, there is an
//! internal `Reader` structure, which takes care of buffering the
//! input stream and implementing basic operations for reading data and
//! moving between fields and lines. (This includes processing comments
//! and parentheses for line extension.) A [`Parser`] then uses a
//! `Reader` to parse records (which includes escape sequence
//! processing). It's not a particularly clean distinction, but as noted
//! above, the file format doesn't really allow one.
//!
//! [RFC 1035 § 5]: https://datatracker.ietf.org/doc/html/rfc1035#section-5
//! [RFC 3597 § 5]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
//! [NLNet]: https://nsd.docs.nlnetlabs.nl/en/latest/reference/grammar.html

use std::io::Read;
use std::rc::Rc;

use crate::class::Class;
use crate::name::Name;
use crate::rr::{Rdata, Ttl, Type};

mod character_string;
mod directive;
pub mod error;
mod escape;
mod name;
mod reader;
mod record;

use error::ErrorKind;
pub use error::{Error, Result};
use reader::{FieldOrEol, Position, Reader};

////////////////////////////////////////////////////////////////////////
// STRUCTURES                                                         //
////////////////////////////////////////////////////////////////////////

/// A parser for [RFC 1035 § 5] DNS zone files.
///
/// A [`Parser`] accepts a stream implementing [`Read`] and can then
/// be iterated to read DNS records and `$INCLUDE` directives from the
/// stream. See the [module-level documentation](`self`) for details
/// and example usage.
///
/// [RFC 1035 § 5]: https://datatracker.ietf.org/doc/html/rfc1035#section-5
pub struct Parser<S> {
    error: bool,
    reader: Reader<S>,
    context: Context,
}

/// Tracks the parse context of a [`Parser`].
///
/// Zone files have a number of context-dependent features. An `@`
/// symbol can be used as a shorthand for the current origin (set with
/// (`$ORIGIN`), and partially qualified domain names are interpreted
/// relative to the origin. Default TTLs can be set with `$TTL`, and
/// omitted TTLs otherwise default to the previous record's TTL. Omitted
/// classes default to the previous record's class. Omitted owner names
/// default to the previous owner. This structure encapsulates all this
/// information.
#[derive(Clone, Default)]
struct Context {
    origin: Option<Rc<Name>>,
    previous_owner: Option<Rc<Name>>,
    previous_ttl: Option<Ttl>,
    previous_class: Option<Class>,
    default_ttl: Option<Ttl>,
}

/// A line parsed from a zone file, as returned by [`Parser::next`].
///
/// This actually represents a logical line; if parentheses are used, it
/// may be several physical lines in the file. Furthermore, only lines
/// that require the caller's attention (records and `$INCLUDE`
/// directives) are returned. Blank lines and `$TTL` directives, for
/// instance, are processed internally and are not reported through this
/// data type.
#[derive(Clone, Debug)]
pub enum Line {
    Include(Include),
    Record(ParsedRr),
}

/// A parsed `$INCLUDE` directive.
#[derive(Clone, Debug)]
pub struct Include {
    pub line: usize,
    pub path: Vec<u8>,
    pub origin: Option<Rc<Name>>,
}

/// Parsed resource record data.
#[derive(Clone, Debug)]
pub struct ParsedRr {
    pub line: usize,
    pub owner: Rc<Name>,
    pub ttl: Ttl,
    pub class: Class,
    pub rr_type: Type,
    pub rdata: Box<Rdata>,
}

////////////////////////////////////////////////////////////////////////
// PARSER CONSTRUCTION AND ITERATION                                  //
////////////////////////////////////////////////////////////////////////

impl<S: Read> Parser<S> {
    /// Creates a new [`Parser`] to read a zone file from the provided
    /// stream.
    pub fn new(stream: S) -> Self {
        Self {
            error: false,
            reader: Reader::new(stream),
            context: Context::default(),
        }
    }

    /// Converts this [`Parser`] into an iterator that produces only
    /// resource records. Any `$INCLUDE` directives found will trigger
    /// an ["include not supported"](`ErrorKind::IncludeNotSupported`)
    /// error.
    pub fn records_only(self) -> RecordsOnly<S> {
        RecordsOnly { parser: self }
    }

    /// An internal helper to parse a single line of a zone file.
    fn parse_line(&mut self) -> Result<Option<Line>> {
        if self.reader.peek_octet()? == Some(b'$') {
            self.parse_directive()
                .map(|maybe_include| maybe_include.map(Line::Include))
        } else {
            self.parse_record_or_empty()
                .map(|maybe_line| maybe_line.map(Line::Record))
        }
    }

    /// An internal helper to parse lines until one with returnable data
    /// is found.
    fn parse_lines_until_returnable_data_found(&mut self) -> Result<Option<Line>> {
        while !self.reader.at_eof()? {
            if let Some(record) = self.parse_line()? {
                return Ok(Some(record));
            }
        }

        // If we're here, we're at the end of the input.
        Ok(None)
    }
}

impl<S: Read> Iterator for Parser<S> {
    type Item = Result<Line>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error {
            // In this module, we don't try to guarantee that internal
            // state is consistent after an error. Hence, if an error
            // has already occurred, then we stop immediately.
            return None;
        }

        match self.parse_lines_until_returnable_data_found() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => {
                self.error = true;
                Some(Err(e))
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////
// RECORDS-ONLY ITERATOR                                              //
////////////////////////////////////////////////////////////////////////

/// An iterator that parses only resource records from a zone file and
/// returns an [error](`ErrorKind::IncludeNotSupported`) if an
/// `$INCLUDE` directive is found. See [`Parser::records_only`].
pub struct RecordsOnly<S> {
    parser: Parser<S>,
}

impl<S: Read> Iterator for RecordsOnly<S> {
    type Item = Result<ParsedRr>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parser.next() {
            Some(Ok(Line::Record(rr))) => Some(Ok(rr)),
            Some(Ok(Line::Include(include))) => {
                // We set the error flag on the underlying parser so
                // that iteration ends.
                self.parser.error = true;
                Some(Err(Error::new(
                    Position {
                        line: include.line,
                        column: 1,
                    },
                    ErrorKind::IncludeNotSupported,
                )))
            }
            Some(Err(e)) => Some(Err(e)),
            None => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::Parser;

    /// A helper used throughout the [`zone_file`](`super`) module's
    /// tests.
    pub(super) fn make_parser(data: &[u8]) -> Parser<Cursor<&[u8]>> {
        Parser::new(Cursor::new(data))
    }
}
