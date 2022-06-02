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

//! Parsing of `<character-string>`s.

use std::io::Read;

use arrayvec::ArrayVec;

use super::{Error, ErrorKind, Parser, Result};
use crate::rr::rdata::CharacterString;

impl<S: Read> Parser<S> {
    /// Parses an [RFC 1035 § 3.3] `<character-string>`. Such a string
    /// may be quoted or unquoted ([RFC 1035 § 5.1]). This method
    /// expects the caller to skip to the next field before calling it;
    /// if it immediately encounters a field-ending character, it will
    /// return an empty `<character-string>`, which is probably not what
    /// you want.
    ///
    /// [RFC 1035 § 3.3]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3
    /// [RFC 1035 § 5.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-5.1
    pub(super) fn parse_character_string(&mut self) -> Result<Box<CharacterString>> {
        if let Some(b'"') = self.reader.peek_octet()? {
            self.parse_quoted_character_string()
        } else {
            self.parse_unquoted_character_string()
        }
    }

    /// Parses a quoted `<character-string>`. The caller is expected to
    /// have seen, but not consumed, the opening `"`.
    fn parse_quoted_character_string(&mut self) -> Result<Box<CharacterString>> {
        // Save the position before discarding the opening quote.
        let start_position = self.reader.position();
        self.reader.read_octet()?;
        let mut character_string = ArrayVec::<u8, 255>::new();
        loop {
            let character_position = self.reader.position();
            if let Some(octet) = self.reader.read_octet()? {
                if octet == b'\\' {
                    let escaped_octet = self.parse_escape()?;
                    character_string.try_push(escaped_octet).map_err(|_| {
                        Error::new(start_position, ErrorKind::CharacterStringTooLong)
                    })?;
                } else if octet == b'"' {
                    // Note that we don't care whether a field-ending
                    // character (e.g. whitespace) follows; the closing
                    // quote is sufficient to end the field. This
                    // follows BIND9, in which e.g. "test"txt is a valid
                    // representation of TXT RDATA containing two
                    // <character-string>s, "test" and "txt".
                    break;
                } else {
                    character_string.try_push(octet).map_err(|_| {
                        Error::new(start_position, ErrorKind::CharacterStringTooLong)
                    })?;
                }
            } else {
                return Err(Error::new(
                    character_position,
                    ErrorKind::EofInQuotedCharacterString,
                ));
            }
        }
        Ok(character_string.as_slice().to_vec().try_into().unwrap())
    }

    /// Parses an unquoted `<character-string>`.
    fn parse_unquoted_character_string(&mut self) -> Result<Box<CharacterString>> {
        let start_position = self.reader.position();
        let mut character_string = ArrayVec::<u8, 255>::new();
        while let Some(octet) = self.reader.read_field_octet()? {
            if octet == b'\\' {
                let escaped_octet = self.parse_escape()?;
                character_string
                    .try_push(escaped_octet)
                    .map_err(|_| Error::new(start_position, ErrorKind::CharacterStringTooLong))?;
            } else {
                character_string
                    .try_push(octet)
                    .map_err(|_| Error::new(start_position, ErrorKind::CharacterStringTooLong))?;
            }
        }
        Ok(character_string.as_slice().to_vec().try_into().unwrap())
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::super::tests::make_parser;
    use super::*;

    const LONG_UNQUOTED: &[u8; 256] =
        b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
        xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
        xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
        xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    #[test]
    fn parsing_unquoted_strings_works() {
        assert_eq!(
            make_parser(b"test\\000 string")
                .parse_character_string()
                .unwrap()
                .octets(),
            b"test\x00"
        );
    }

    #[test]
    fn parsing_quoted_strings_works() {
        assert_eq!(
            make_parser(b"\"test\\000 str\"ing")
                .parse_character_string()
                .unwrap()
                .octets(),
            b"test\x00 str"
        );
    }

    #[test]
    fn parser_rejects_unmatched_quotes() {
        assert!(matches!(
            make_parser(b"\"test").parse_character_string(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::EofInQuotedCharacterString,
        ));
    }

    #[test]
    fn unquoted_parser_rejects_strings_that_are_too_long() {
        assert!(matches!(
            make_parser(LONG_UNQUOTED).parse_unquoted_character_string(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::CharacterStringTooLong,
        ));
    }

    #[test]
    fn quoted_parser_rejects_strings_that_are_too_long() {
        let mut long_quoted = vec![b'"'];
        long_quoted.extend_from_slice(LONG_UNQUOTED);
        long_quoted.push(b'"');
        assert!(matches!(
            make_parser(&long_quoted).parse_quoted_character_string(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::CharacterStringTooLong,
        ));
    }
}
