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

use super::{Error, ErrorKind, FieldOrEol, Parser, Result};

impl<S: Read> Parser<S> {
    /// Parses a zone file directive. This expects that the caller
    /// has already detected, but not consumed, the leading `$`. When
    /// successful, this method reads through the end of the line.
    pub(super) fn parse_directive(&mut self) -> Result<()> {
        // Check for all known directives.
        if self.reader.expect_field_case_insensitive(b"$ORIGIN")? {
            self.parse_origin_directive()?;
        } else if self.reader.expect_field_case_insensitive(b"$TTL")? {
            self.parse_ttl_directive()?;
        } else {
            return Err(Error::new(
                self.reader.position(),
                ErrorKind::UnknownDirective,
            ));
        }

        // If we are here, a directive has been successfully parsed. Now
        // we check that there's no additional data in the line.
        if self.reader.skip_to_next_field_or_through_eol()? != FieldOrEol::Eol {
            return Err(Error::new(self.reader.position(), ErrorKind::ExpectedEol));
        }

        Ok(())
    }

    // Note that for these subroutines, the skip to the next field is
    // performed by the callee, not the caller. Like with the RDATA
    // parsing methods, this is so that the appropriate error message
    // can be given (see the note in the record module).

    /// Parses an `$ORIGIN` directive. This performs the skip to the
    /// next field itself.
    fn parse_origin_directive(&mut self) -> Result<()> {
        self.reader.skip_to_next_field(ErrorKind::ExpectedName)?;
        let name = self.parse_name()?;
        self.context.origin = Some(name);
        Ok(())
    }

    /// Parses a `$TTL` directive. This performs the skip to the
    /// next field itself.
    fn parse_ttl_directive(&mut self) -> Result<()> {
        self.reader.skip_to_next_field(ErrorKind::ExpectedTtl)?;
        let ttl: u32 = self.reader.read_field(ErrorKind::InvalidTtl)?;
        self.context.default_ttl = Some(ttl.into());
        Ok(())
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
