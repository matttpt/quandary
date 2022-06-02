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

//! Parsing of escape sequences.

use std::io::Read;

use super::{Error, ErrorKind, Parser, Position, Result};

impl<S: Read> Parser<S> {
    /// Parses an escape sequence (see [RFC 1035 § 5.1] and [RFC 4343 §
    /// 2.1]. This assumes that the caller has already seen and
    /// discarded the leading `\`.
    ///
    /// [RFC 1035 § 5.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-5.1
    /// [RFC 4343 § 2.1]: https://datatracker.ietf.org/doc/html/rfc4343#section-2.1
    pub(super) fn parse_escape(&mut self) -> Result<u8> {
        let start_position = self.reader.position();
        if let Some(first) = self.reader.read_octet()? {
            if first.is_ascii_digit() {
                self.parse_decimal_escape(first, start_position)
            } else {
                Ok(first)
            }
        } else {
            Err(Error::new(start_position, ErrorKind::EofInEscape))
        }
    }

    /// Parses a three-decimal-digit escape sequence after the caller
    /// has already read the first digit (`first`). It is expected that
    /// `first` has already been verified to be an ASCII digit.
    fn parse_decimal_escape(&mut self, first: u8, start_position: Position) -> Result<u8> {
        let mut remaining_two = [0, 0];
        if self.reader.read(&mut remaining_two)? {
            if !remaining_two.iter().all(u8::is_ascii_digit) {
                return Err(Error::new(
                    start_position,
                    ErrorKind::EscapeNeedsThreeDigits,
                ));
            }
            let hundreds = (first - b'0') as usize;
            let tens = (remaining_two[0] - b'0') as usize;
            let ones = (remaining_two[1] - b'0') as usize;
            let value = 100 * hundreds + 10 * tens + ones;
            value
                .try_into()
                .map_err(|_| Error::new(start_position, ErrorKind::EscapeValueOutOfRange))
        } else {
            Err(Error::new(start_position, ErrorKind::EofInEscape))
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::super::tests::make_parser;
    use super::*;

    #[test]
    fn parsing_works_for_digits() {
        assert_eq!(make_parser(b"0234").parse_escape().unwrap(), 23);
    }

    #[test]
    fn parsing_works_for_other_octets() {
        assert_eq!(make_parser(b"\x0023").parse_escape().unwrap(), 0);
    }

    #[test]
    fn parsing_fails_without_enough_data() {
        for data in [b"".as_slice(), b"0".as_slice(), b"01".as_slice()] {
            assert!(matches!(
                make_parser(data).parse_escape(),
                Err(Error::Syntax(details)) if details.kind == ErrorKind::EofInEscape,
            ));
        }
    }

    #[test]
    fn parsing_fails_without_enough_digits() {
        // Note that each test string is three characters long, since
        // the unexpected EOF error takes precedence.
        for data in [b"0xx".as_slice(), b"01x".as_slice()] {
            assert!(matches!(
                make_parser(data).parse_escape(),
                Err(Error::Syntax(details)) if details.kind == ErrorKind::EscapeNeedsThreeDigits,
            ));
        }
    }

    #[test]
    fn parsing_fails_for_values_out_of_range() {
        assert!(matches!(
            make_parser(b"256").parse_escape(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::EscapeValueOutOfRange,
        ));
    }
}
