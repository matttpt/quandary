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

//! Parsing of zone file `$`-directives.

use std::io::Read;

use super::{Error, ErrorKind, FieldOrEol, Include, Line, LineContent, Parser, Position, Result};

impl<S: Read> Parser<S> {
    /// Parses a zone file directive. This expects that the caller
    /// has already detected, but not consumed, the leading `$`. When
    /// successful, this method reads through the end of the line.
    pub(super) fn parse_directive(&mut self) -> Result<Option<Line>> {
        let line = if self.reader.expect_field_case_insensitive(b"$ORIGIN")? {
            self.parse_origin_directive()?;
            None
        } else if self.reader.expect_field_case_insensitive(b"$TTL")? {
            self.parse_ttl_directive()?;
            None
        } else if self.reader.expect_field_case_insensitive(b"$INCLUDE")? {
            Some(self.parse_include_directive()?)
        } else {
            return Err(Error::new(
                self.reader.position(),
                ErrorKind::UnknownDirective,
            ));
        };
        Ok(line)
    }

    // Note that for these subroutines, the skip to the next field is
    // performed by the callee, not the caller. Like with the RDATA
    // parsing methods, this is so that the appropriate error message
    // can be given (see the note in the record module). Furthermore,
    // as with RDATA parsing, these methods consume the line ending.

    /// Parses an `$ORIGIN` directive.
    fn parse_origin_directive(&mut self) -> Result<()> {
        self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
        let name = self.parse_name()?;
        self.reader.expect_eol()?;
        self.context.origin = Some(name);
        Ok(())
    }

    /// Parses a `$TTL` directive.
    fn parse_ttl_directive(&mut self) -> Result<()> {
        self.reader.skip_to_next_field(ErrorKind::ExpectedTtl)?;
        let ttl: u32 = self.reader.read_field(ErrorKind::InvalidTtl)?;
        self.reader.expect_eol()?;
        self.context.default_ttl = Some(ttl.into());
        Ok(())
    }

    /// Parses an `$INCLUDE` directive.
    fn parse_include_directive(&mut self) -> Result<Line> {
        let line = self.reader.position().line;
        self.reader
            .skip_to_next_field(ErrorKind::ExpectedIncludePath)?;
        let path = self.parse_include_path()?;
        let origin = if self.reader.skip_to_next_field_or_through_eol()? == FieldOrEol::Eol {
            self.context.origin.clone()
        } else {
            let origin = self.parse_name()?;
            self.reader.expect_eol()?;
            Some(origin)
        };
        Ok(Line {
            number: line,
            content: LineContent::Include(Include { path, origin }),
        })
    }

    /// Parses the path in an `$INCLUDE` directive.
    ///
    /// RFC 1035 does not provide details about the format of the path.
    /// BIND, NSD, and Knot all allow quoted paths, and BIND and Knot
    /// appear to accept at least some escape sequences. We follow Knot
    /// here, since it seems to treat the path as if it were a
    /// `<character-string>` (though without the 255-octet limit) and to
    /// accept all the same escape sequences. This allows any octet
    /// sequence to be expressed.
    fn parse_include_path(&mut self) -> Result<Vec<u8>> {
        if let Some(b'"') = self.reader.peek_octet()? {
            self.parse_quoted_include_path()
        } else {
            self.parse_unquoted_include_path()
        }
    }

    /// Parses a quoted include path. The caller is expected to have
    /// seen, but not consumed, the opening `"`. This functions like
    /// [`Parser::parse_quoted_character_string`], except that it works
    /// with a [`Vec`] instead.
    fn parse_quoted_include_path(&mut self) -> Result<Vec<u8>> {
        // Save the position before discarding the opening quote.
        let start_position = self.reader.position();
        self.reader.read_octet()?;
        let mut path = Vec::new();
        loop {
            let character_position = self.reader.position();
            if let Some(octet) = self.reader.read_octet()? {
                if octet == b'\\' {
                    push_path_octet(self.parse_escape()?, &mut path, start_position)?;
                } else if octet == b'"' {
                    break;
                } else {
                    push_path_octet(octet, &mut path, start_position)?;
                }
            } else {
                return Err(Error::new(
                    character_position,
                    ErrorKind::EofInQuotedIncludePath,
                ));
            }
        }
        Ok(path)
    }

    /// Parses an unquoted include path. This functions like
    /// [`Parser::parse_unquoted_character_string`], except that it
    /// works with a [`Vec`] instead.
    fn parse_unquoted_include_path(&mut self) -> Result<Vec<u8>> {
        let start_position = self.reader.position();
        let mut path = Vec::new();
        while let Some(octet) = self.reader.read_field_octet()? {
            let effective_octet = if octet == b'\\' {
                self.parse_escape()?
            } else {
                octet
            };
            push_path_octet(effective_octet, &mut path, start_position)?;
        }
        Ok(path)
    }
}

/// The maximum length of a path in an `$INCLUDE` directive. This is
/// used to prevent OOM-based DoS attacks. The current value should be
/// longer than any reasonable path seen in the wild (indeed, `PATH_MAX`
/// on Linux is only 4,096!).
const INCLUDE_PATH_MAX: usize = 65_536;

/// Appends an octet to the back of the given path buffer, failing if
/// the result would exceed [`INCLUDE_PATH_MAX`] in length.
fn push_path_octet(octet: u8, path: &mut Vec<u8>, start_position: Position) -> Result<()> {
    if path.len() < INCLUDE_PATH_MAX {
        path.push(octet);
        Ok(())
    } else {
        Err(Error::new(start_position, ErrorKind::IncludePathTooLong))
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use crate::name::Name;

    use super::super::tests::make_parser;
    use super::*;

    #[test]
    fn parsing_origin_directive_works() {
        let mut parser = make_parser(b"$ORIGIN test.");
        assert!(parser.context.origin.is_none());
        parser.parse_directive().unwrap();
        assert_eq!(
            *parser.context.origin.unwrap(),
            *"test.".parse::<Box<Name>>().unwrap()
        );
    }

    #[test]
    fn parsing_ttl_directive_works() {
        let mut parser = make_parser(b"$TTL 3600");
        assert!(parser.context.default_ttl.is_none());
        parser.parse_directive().unwrap();
        assert_eq!(parser.context.default_ttl, Some(3600.into()));
    }

    #[test]
    fn parsing_include_directive_works() {
        let mut parser = make_parser(b"$INCLUDE /path/to/file.zone");
        let line = parser.parse_directive().unwrap().unwrap();
        assert_eq!(line.number, 1);
        match line.content {
            LineContent::Include(include) => {
                assert_eq!(include.path, b"/path/to/file.zone");
                assert!(include.origin.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_include_directive_with_origin_works() {
        let mut parser = make_parser(b"$INCLUDE /path/to/file.zone origin.test.");
        let line = parser.parse_directive().unwrap().unwrap();
        assert_eq!(line.number, 1);
        match line.content {
            LineContent::Include(include) => {
                assert_eq!(include.path, b"/path/to/file.zone");
                assert_eq!(
                    include.origin.unwrap().as_ref(),
                    "origin.test.".parse::<Box<Name>>().unwrap().as_ref(),
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parsing_unquoted_include_path_works() {
        assert_eq!(
            make_parser(b"test\\000 path").parse_include_path().unwrap(),
            b"test\x00",
        );
    }

    #[test]
    fn parsing_quoted_include_path_works() {
        assert_eq!(
            make_parser(b"\"test\\000 include\"path")
                .parse_include_path()
                .unwrap(),
            b"test\x00 include",
        );
    }

    #[test]
    fn include_path_parser_rejects_unmatched_quotes() {
        assert!(matches!(
            make_parser(b"\"test path").parse_include_path(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::EofInQuotedIncludePath,
        ));
    }

    #[test]
    fn unquoted_include_path_parser_rejects_paths_that_are_too_long() {
        let too_long = vec![b'x'; INCLUDE_PATH_MAX + 1];
        assert!(matches!(
            make_parser(&too_long).parse_unquoted_include_path(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::IncludePathTooLong,
        ));
    }

    #[test]
    fn quoted_include_path_parser_rejects_paths_that_are_too_long() {
        let mut too_long = Vec::with_capacity(INCLUDE_PATH_MAX + 3);
        too_long.push(b'"');
        too_long.resize(INCLUDE_PATH_MAX + 2, b'x');
        too_long.push(b'"');
        assert!(matches!(
            make_parser(&too_long).parse_quoted_include_path(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::IncludePathTooLong,
        ));
    }

    #[test]
    fn parser_handles_unknown_directives() {
        assert!(matches!(
            make_parser(b"$FROBNICATE 123").parse_directive(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::UnknownDirective,
        ));
        assert!(matches!(
            make_parser(b"not even a directive").parse_directive(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::UnknownDirective,
        ));
    }
}
