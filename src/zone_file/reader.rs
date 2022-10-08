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

//! The [`Reader`] structure.
//!
//! See the [`zone_file` module-level documentation](`super`) for
//! implementation details about how the [`Reader`] is used.

use std::io::{self, Read};
use std::str::{self, FromStr};

use super::{Error, ErrorKind, Result};

////////////////////////////////////////////////////////////////////////
// STRUCTURES                                                         //
////////////////////////////////////////////////////////////////////////

/// Performs low-level reading of DNS zone files.
///
/// The [`Reader`] takes care of buffering the input stream and
/// implementing basic operations for reading data and moving between
/// fields and lines in a zone file. This includes processing comments
/// and parentheses for line extension.
///
/// See the [`zone_file` module-level documentation](`super`) for
/// details about how the [`Reader`] is used.
pub(super) struct Reader<S> {
    stream: S,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    in_parens: bool,
    position: Position,
}

/// Records the current human-readable position (line and column) in a
/// zone file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Position {
    pub line: usize,
    pub column: usize,
}

////////////////////////////////////////////////////////////////////////
// BUFFER PARAMETERS                                                  //
////////////////////////////////////////////////////////////////////////

/// The initial buffer size allocated for a new [`Reader`].
const INITIAL_BUFFER_SIZE: usize = 16_384;

/// The maximum length of a field (in octets) that the
/// [`Reader::read_field`] will accept. (This is to prevent OOM-based
/// DoS attacks.)
const MAX_READ_FIELD_SIZE: usize = 65_536;

////////////////////////////////////////////////////////////////////////
// READER IMPLEMENTATION                                              //
////////////////////////////////////////////////////////////////////////

impl<S: Read> Reader<S> {
    ////////////////////////////////////////////////////////////////////
    // BASICS                                                         //
    ////////////////////////////////////////////////////////////////////

    /// Constructs a new [`Reader`] from the given stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: vec![0; INITIAL_BUFFER_SIZE],
            start: 0,
            end: 0,
            in_parens: false,
            position: Position { line: 1, column: 1 },
        }
    }

    /// Returns the current [`Position`] of the stream.
    pub fn position(&self) -> Position {
        self.position
    }

    /// Returns whether the stream is at end-of-file.
    pub fn at_eof(&mut self) -> io::Result<bool> {
        self.peek_octet().map(|octet| octet.is_none())
    }

    ////////////////////////////////////////////////////////////////////
    // BUFFERING                                                      //
    ////////////////////////////////////////////////////////////////////

    /// Returns how many octets are buffered but unconsumed.
    fn buffered(&self) -> usize {
        self.end - self.start
    }

    /// Shifts all buffered but unconsumed data to the beginning of the
    /// buffer.
    fn shift(&mut self) {
        if self.start != 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Tries to fill the buffer with at least `target` octets. When
    /// there are no I/O errors, this returns `true` when at least
    /// `target` octets are read, and `false` when end-of-file is
    /// reached first.
    fn try_fill(&mut self, target: usize) -> io::Result<bool> {
        if self.buffered() < target {
            self.shift();
            if self.buf.len() < target {
                self.buf.resize(target, 0);
            }
            loop {
                let n_read = self.stream.read(&mut self.buf[self.end..])?;
                self.end += n_read;
                if self.end >= target {
                    break;
                } else if n_read == 0 {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    ////////////////////////////////////////////////////////////////////
    // PEEKING AND READING OF RAW DATA                                //
    ////////////////////////////////////////////////////////////////////

    /// Returns `len` octets starting at `index` (where `0` is the first
    /// unconsumed octet in the stream), or `None` if end-of-file occurs
    /// first. No octets are consumed.
    ///
    /// Note that reads of zero length at the EOF position will return
    /// something, but reads of zro length *beyond* the EOF position
    /// will return `None`.
    fn peek_at(&mut self, index: usize, len: usize) -> io::Result<Option<&[u8]>> {
        if self.try_fill(index + len)? {
            Ok(Some(
                &self.buf[self.start + index..self.start + index + len],
            ))
        } else {
            Ok(None)
        }
    }

    /// Returns `len` octets, starting with the first unconsumed octet in
    /// the stream, without consuming them, or `None` if end-of-file
    /// occurs first. No octets are consumed.
    pub fn peek(&mut self, len: usize) -> io::Result<Option<&[u8]>> {
        self.peek_at(0, len)
    }

    /// Returns the octet at `index` (where `0` is the first unconsumed
    /// octet in the stream), or `None` if it is beyond the end of the
    /// stream. No octets are consumed.
    fn peek_octet_at(&mut self, index: usize) -> io::Result<Option<u8>> {
        if self.try_fill(index + 1)? {
            Ok(Some(self.buf[self.start + index]))
        } else {
            Ok(None)
        }
    }

    /// Returns the next unconsumed octet in the stream without
    /// consuming it, or `None` if the stream is at end-of-file.
    pub fn peek_octet(&mut self) -> io::Result<Option<u8>> {
        self.peek_octet_at(0)
    }

    /// Consumes and returns the next consumed octet in the stream, or
    /// returns `None` if the stream is at end-of-file.
    ///
    /// This method handles newline characters when computing the change
    /// to the line/column position.
    pub fn read_octet(&mut self) -> io::Result<Option<u8>> {
        if self.try_fill(1)? {
            let octet = self.buf[self.start];
            self.start += 1;
            if octet == b'\n' {
                self.position.line += 1;
                self.position.column = 1;
            } else {
                self.position.column += 1;
            }
            Ok(Some(octet))
        } else {
            Ok(None)
        }
    }

    /// If there are enough unconsumed octets in the stream, this
    /// consumes `into.len()` octets, writes them to `into`, and returns
    /// `true`. Otherwise, nothing is written, and `false` is returned.
    ///
    /// Note that when computing the change in the line/column position,
    /// this method assumes that the read data contains no newlines.
    pub fn read(&mut self, into: &mut [u8]) -> io::Result<bool> {
        if self.try_fill(into.len())? {
            into.copy_from_slice(&self.buf[self.start..self.start + into.len()]);
            self.start += into.len();
            self.position.column += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    ////////////////////////////////////////////////////////////////////
    // EOL DETECTION                                                  //
    ////////////////////////////////////////////////////////////////////

    /// Detects a line ending at `index` (where `0` is the first
    /// unconsumed octet in the stream). If `index` is the start of a
    /// line ending, then the length of the line ending is returned.
    /// This will be `0` for end-of-file (both when `index` is at
    /// end-of-file and past end-of-file); `1` for a newline character;
    /// or or `2` for a carriage return plus newline. If `index` is not
    /// the start of a line ending, `None` is returned.
    fn get_eol_at(&mut self, index: usize) -> io::Result<Option<usize>> {
        let peek_1 = self.peek_octet_at(index)?;
        if peek_1 == None {
            Ok(Some(0))
        } else if peek_1 == Some(b'\n') {
            Ok(Some(1))
        } else if self.peek_at(index, 2)? == Some(b"\r\n") {
            Ok(Some(2))
        } else {
            Ok(None)
        }
    }

    /// Detects a line ending at the current stream position. See
    /// [`Reader::get_eol_at`] for more details.
    fn get_eol(&mut self) -> io::Result<Option<usize>> {
        self.get_eol_at(0)
    }

    ////////////////////////////////////////////////////////////////////
    // READING OF FIELDS                                              //
    ////////////////////////////////////////////////////////////////////

    /// Returns whether `index` (where `0` is the current stream
    /// position) marks the end of a zone file field. See
    /// [`Reader::at_field_end`] for more.
    fn at_field_end_at(&mut self, index: usize) -> io::Result<bool> {
        // Note that since EOF counts as EOL, there is at least one
        // octet in the buffer if we are not at EOL.
        if self.get_eol_at(index)?.is_some() || ends_field(self.buf[self.start + index]) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns whether the current stream position marks the end of a
    /// zone file field. This occurs at end-of-file, ends of lines, and
    /// field-ending characters (see [`ends_field`]).
    fn at_field_end(&mut self) -> io::Result<bool> {
        self.at_field_end_at(0)
    }

    /// Checks whether the next field in the stream is equal to `field`
    /// using the provided comparison function `comparison`. If equal,
    /// the field is consumed.
    ///
    /// Note that when computing the change in the line/column position,
    /// this method assumes that the read data contains no newlines.
    fn expect_field_impl(
        &mut self,
        field: &[u8],
        comparison: impl Fn(&[u8], &[u8]) -> bool,
    ) -> io::Result<bool> {
        if let Some(peek) = self.peek(field.len())? {
            if comparison(peek, field) && self.at_field_end_at(field.len())? {
                self.start += field.len();
                self.position.column += field.len();
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Checks whether the next field in the stream is exactly (bitwise)
    /// equal to `field`. If equal, the field is consumed.
    ///
    /// Note that when computing the change in the line/column position,
    /// this method assumes that the read data contains no newlines.
    pub fn expect_field(&mut self, field: &[u8]) -> io::Result<bool> {
        self.expect_field_impl(field, <[u8]>::eq)
    }

    /// Checks whether the next field in the stream is
    /// case-insensitively equal (in ASCII) to `field`. If equal, the
    /// field is consumed.
    ///
    /// Note that when computing the change in the line/column position,
    /// this method assumes that the read data contains no newlines.
    pub fn expect_field_case_insensitive(&mut self, field: &[u8]) -> io::Result<bool> {
        self.expect_field_impl(field, <[u8]>::eq_ignore_ascii_case)
    }

    /// Consumes a field from the stream, converting it to UTF-8 and
    /// then parsing it into a value of type `T`. If parsing fails,
    /// nothing is consumed.
    ///
    /// One should use [`Reader::skip_to_next_field`] to ensure that
    /// the stream is positioned at field to parse. If instead the
    /// stream is positioned at end-of-file, a line end, or a
    /// field-ending character, this method will attempt to parse an
    /// empty string, which (based on the [`FromStr`] implementation of
    /// `T`) will likely fail.
    ///
    /// The parameter `or_else` is a function used to convert
    /// `<T as FromStr>::Err` into an [`ErrorKind`] when parsing fails.
    pub fn read_field<T, F>(&mut self, or_else: F) -> Result<T>
    where
        T: FromStr,
        F: FnOnce(T::Err) -> ErrorKind,
    {
        let mut len = 0;
        while !self.at_field_end_at(len)? {
            len += 1;
            if len > MAX_READ_FIELD_SIZE {
                // This field is unreasonably long. We fail to guard
                // against OOM-based DoS attacks.
                return Err(Error::new(self.position, ErrorKind::FieldTooLong));
            }
        }
        let utf8 = match str::from_utf8(&self.buf[self.start..self.start + len]) {
            Ok(utf8) => utf8,
            Err(e) => return Err(Error::new(self.position, ErrorKind::BadUtf8(e))),
        };
        match utf8.parse() {
            Ok(field) => {
                // NOTE: There's no real-world case for using this
                // method to parse a field whose valid values include
                // non-ASCII strings. Thus we assume here that the
                // length in octets and the number of characters a that
                // a human reads are the same.
                self.start += len;
                self.position.column += len;
                Ok(field)
            }
            Err(e) => Err(Error::new(self.position, or_else(e))),
        }
    }

    /// Checks whether the stream is at a field end, returning `None` if
    /// so and consuming and returning the next octet if not.
    pub fn read_field_octet(&mut self) -> io::Result<Option<u8>> {
        if self.at_field_end()? {
            Ok(None)
        } else {
            // If we are not at the end of a field, we are not at EOF;
            // therefore, there is at least one octet in the buffer.
            let octet = self.buf[self.start];
            self.start += 1;
            self.position.column += 1;
            Ok(Some(octet))
        }
    }

    ////////////////////////////////////////////////////////////////////
    // "NAVIGATION" AMONG FIELDS AND LINES                            //
    ////////////////////////////////////////////////////////////////////

    /// Consumes whitespace (excluding newlines) from the stream until a
    /// non-whitespace character is reached. Returns `true` if
    /// whitespace was consumed and `false` if not.
    pub fn skip_whitespace(&mut self) -> io::Result<bool> {
        let mut skipped = false;
        while self.peek_octet()?.map_or(false, is_whitespace) {
            skipped = true;
            self.start += 1;
            self.position.column += 1;
        }
        Ok(skipped)
    }

    /// The underlying implementation for [`Reader::skip_to_eol`] and
    /// [`Reader::skip_through_eol`].
    fn eol_skipping_impl(&mut self, through_eol: bool) -> io::Result<()> {
        let mut eol = self.get_eol()?;
        loop {
            if let Some(eol_len) = eol {
                if eol_len > 0 && through_eol {
                    self.start += eol_len;
                    self.position.line += 1;
                    self.position.column = 1;
                }
                return Ok(());
            } else {
                self.start += 1;
                self.position.column += 1;
                eol = self.get_eol()?;
            }
        }
    }

    /// Consumes data from the stream up to, but not including, the next
    /// line ending.
    fn skip_to_eol(&mut self) -> io::Result<()> {
        self.eol_skipping_impl(false)
    }

    /// Consumes data from the stream up to and including the next line
    /// ending.
    fn skip_through_eol(&mut self) -> io::Result<()> {
        self.eol_skipping_impl(true)
    }

    /// The underlying implementation for [`Reader::skip_to_next_field`]
    /// and [`Reader::skip_to_next_field_or_through_eol`].
    fn field_or_eol_skipping_impl(&mut self, through_eol: bool) -> Result<FieldOrEol> {
        loop {
            self.skip_whitespace()?;
            if let Some(eol_len) = self.get_eol()? {
                if self.in_parens {
                    if eol_len == 0 {
                        return Err(Error::new(self.position, ErrorKind::EofBeforeCloseParen));
                    } else {
                        self.start += eol_len;
                        self.position.line += 1;
                        self.position.column = 1;
                    }
                } else {
                    if through_eol && eol_len > 0 {
                        self.start += eol_len;
                        self.position.line += 1;
                        self.position.column = 1;
                    }
                    return Ok(FieldOrEol::Eol);
                }
            } else {
                // Since EOF counts as an EOL, not at EOL implies that
                // there is at least one octet in the buffer.
                let octet = self.buf[self.start];
                if octet == b';' {
                    if self.in_parens {
                        self.skip_through_eol()?;
                    } else {
                        if through_eol {
                            self.skip_through_eol()?;
                        } else {
                            self.skip_to_eol()?;
                        }
                        return Ok(FieldOrEol::Eol);
                    }
                } else if octet == b'(' {
                    if self.in_parens {
                        return Err(Error::new(self.position, ErrorKind::NestedParens));
                    } else {
                        self.in_parens = true;
                        self.start += 1;
                        self.position.column += 1;
                    }
                } else if octet == b')' {
                    if !self.in_parens {
                        return Err(Error::new(self.position, ErrorKind::UnmatchedCloseParen));
                    } else {
                        self.in_parens = false;
                        self.start += 1;
                        self.position.column += 1;
                    }
                } else {
                    // If not one of the previously tested characters,
                    // the octet must be field data.
                    return Ok(FieldOrEol::Field);
                }
            }
        }
    }

    /// Consumes data from the stream until the next field, or until and
    /// including the next line ending (whichever comes first). This
    /// method processes parentheses for extending lines, so newlines
    /// found within parentheses will not be considered. The returned
    /// value indicates which of the two options was encountered first.
    pub fn skip_to_next_field_or_through_eol(&mut self) -> Result<FieldOrEol> {
        self.field_or_eol_skipping_impl(true)
    }

    /// Like [`Reader::skip_to_next_field_or_through_eol`], except that
    /// it does not consume the next line ending if it comes first.
    pub fn skip_to_next_field_or_to_eol(&mut self) -> Result<FieldOrEol> {
        self.field_or_eol_skipping_impl(false)
    }

    /// Consumes data from the stream until the next field on the same
    /// line. If a line ending is found first, an error of kind
    /// `error_on_eol` will be raised at the position of the line
    /// ending. This method processes parentheses for extending lines,
    /// so newlines found within parentheses will not be considered.
    pub fn skip_to_next_field(&mut self, error_on_eol: ErrorKind) -> Result<()> {
        if self.skip_to_next_field_or_to_eol()? != FieldOrEol::Field {
            Err(Error::new(self.position, error_on_eol))
        } else {
            Ok(())
        }
    }

    /// Skips through the end of a line, returning an error of kind
    /// [`ErrorKind::ExpectedEol`] if another field is reached first.
    pub fn expect_eol(&mut self) -> Result<()> {
        if self.skip_to_next_field_or_through_eol()? != FieldOrEol::Eol {
            Err(Error::new(self.position, ErrorKind::ExpectedEol))
        } else {
            Ok(())
        }
    }
}

/// Returns whether `c` is considered whitespace in a zone file.
fn is_whitespace(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Returns whether `c` ends a field in a zone file.
fn ends_field(c: u8) -> bool {
    is_whitespace(c) || c == b'(' || c == b')' || c == b';'
}

/// Indicates whether certain operations stopped at the next field on
/// a line, or at a line ending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FieldOrEol {
    Field,
    Eol,
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::num::IntErrorKind;

    use super::*;

    fn make_reader(data: &[u8]) -> Reader<Cursor<&[u8]>> {
        Reader::new(Cursor::new(data))
    }

    #[test]
    fn peek_at_works_for_ranges_before_eof() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.peek_at(1, 0).unwrap(), Some(b"".as_slice()));
        assert_eq!(reader.peek_at(0, 3).unwrap(), Some(b"tes".as_slice()));
        assert_eq!(reader.peek_at(2, 2).unwrap(), Some(b"st".as_slice()));
        assert_eq!(reader.peek_at(4, 0).unwrap(), Some(b"".as_slice()));
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn peek_at_handles_ranges_beyond_eof() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.peek_at(0, 5).unwrap(), None);
        assert_eq!(reader.peek_at(2, 7).unwrap(), None);
        assert_eq!(reader.peek_at(5, 0).unwrap(), None);
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn peek_octet_at_works_before_eof() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.peek_octet_at(0).unwrap(), Some(b't'));
        assert_eq!(reader.peek_octet_at(3).unwrap(), Some(b't'));
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn peek_octet_at_handles_at_or_after_eof() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.peek_octet_at(4).unwrap(), None);
        assert_eq!(reader.peek_octet_at(7).unwrap(), None);
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn read_octet_works() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.read_octet().unwrap(), Some(b't'));
        assert_eq!(reader.read_octet().unwrap(), Some(b'e'));
        assert_eq!(reader.position, Position { line: 1, column: 3 });
    }

    #[test]
    fn read_octet_handles_newlines() {
        let mut reader = make_reader(b"\n");
        assert_eq!(reader.read_octet().unwrap(), Some(b'\n'));
        assert_eq!(reader.position, Position { line: 2, column: 1 });
    }

    #[test]
    fn read_octet_handles_eof() {
        let mut reader = make_reader(b"");
        assert_eq!(reader.read_octet().unwrap(), None);
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn get_eol_at_works_positively() {
        let mut reader = make_reader(b"abc\nd\re\r\nf");
        assert_eq!(reader.get_eol_at(3).unwrap(), Some(1));
        assert_eq!(reader.get_eol_at(7).unwrap(), Some(2));
        assert_eq!(reader.get_eol_at(10).unwrap(), Some(0));
    }

    #[test]
    fn get_eol_at_works_negatively() {
        let mut reader = make_reader(b"abc\nd\re\r\nf");
        assert_eq!(reader.get_eol_at(0).unwrap(), None);
        assert_eq!(reader.get_eol_at(5).unwrap(), None);
        assert_eq!(reader.get_eol_at(9).unwrap(), None);
    }

    #[test]
    fn at_field_end_at_works_positively_for_single_chars_and_eof() {
        // This tests all characters in the string, the EOF position,
        // and one past the EOF position.
        let single_char_field_enders = b" \t();";
        let mut reader = make_reader(single_char_field_enders);
        for i in 0..=single_char_field_enders.len() + 1 {
            assert!(reader.at_field_end_at(i).unwrap());
        }
    }

    #[test]
    fn at_field_end_at_works_positively_for_newlines() {
        let mut reader = make_reader(b"\n\r\n");
        assert!(reader.at_field_end_at(0).unwrap());
        assert!(reader.at_field_end_at(1).unwrap());
    }

    #[test]
    fn at_field_end_at_works_negatively() {
        // We are sure to include \r without \n!
        let chars = b"abc123\r%^!";
        let mut reader = make_reader(chars);
        for i in 0..chars.len() {
            assert!(!reader.at_field_end_at(i).unwrap());
        }
    }

    #[test]
    fn expect_field_works_positively() {
        let mut reader = make_reader(b"$ORIGIN .");
        assert!(reader.expect_field(b"$ORIGIN").unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 8 });
    }

    #[test]
    fn expect_field_works_negatively() {
        let mut reader = make_reader(b"$ORIGIN .");
        assert!(!reader.expect_field(b"$TTL").unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn expect_field_is_case_sensitive() {
        assert!(!make_reader(b"$origin .").expect_field(b"$ORIGIN").unwrap());
    }

    #[test]
    fn expect_field_case_insensitive_works_positively() {
        let mut reader = make_reader(b"$ORIGIN .");
        assert!(reader.expect_field_case_insensitive(b"$ORIGIN").unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 8 });
    }

    #[test]
    fn expect_field_case_insensitive_works_negatively() {
        let mut reader = make_reader(b"$ORIGIN .");
        assert!(!reader.expect_field_case_insensitive(b"$TTL").unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn expect_field_is_case_insensitive() {
        assert!(make_reader(b"$origin .")
            .expect_field_case_insensitive(b"$ORIGIN")
            .unwrap());
    }

    #[test]
    fn read_field_works_positively() {
        let mut reader = make_reader(b"1234 abcd");
        let number: u32 = reader.read_field(ErrorKind::InvalidInt).unwrap();
        assert_eq!(number, 1234);
        assert_eq!(reader.position, Position { line: 1, column: 5 });
    }

    #[test]
    fn read_field_handles_fromstr_errors() {
        let mut reader = make_reader(b"abcd 1234");
        match reader.read_field::<u32, _>(ErrorKind::InvalidInt) {
            Err(Error::Syntax(details)) => {
                if let ErrorKind::InvalidInt(e) = details.kind {
                    assert_eq!(e.kind(), &IntErrorKind::InvalidDigit);
                } else {
                    panic!();
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn read_field_handles_utf8_errors() {
        let mut reader = make_reader(b"\xff234 abcd");
        assert!(matches!(
            reader.read_field::<u32, _>(ErrorKind::InvalidInt),
            Err(Error::Syntax(details)) if matches!(details.kind, ErrorKind::BadUtf8(_)),
        ));
    }

    #[test]
    fn read_field_limits_field_size() {
        // Make sure that we can read a field of length
        // MAX_READ_FIELD_SIZE. The "ExpectedEol" error is just a
        // placeholder.
        make_reader(&[b'x'; MAX_READ_FIELD_SIZE])
            .read_field::<String, _>(|_| ErrorKind::ExpectedEol)
            .unwrap();

        // Make sure that a field of length MAX_READ_FIELD_SIZE + 1 is
        // rejected.
        assert!(matches!(
            make_reader(&[b'x'; MAX_READ_FIELD_SIZE + 1])
                .read_field::<String, _>(|_| ErrorKind::ExpectedEol),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::FieldTooLong,
        ));
    }

    #[test]
    fn read_field_octet_works_positively() {
        let mut reader = make_reader(b"test");
        assert_eq!(reader.read_field_octet().unwrap(), Some(b't'));
        assert_eq!(reader.read_field_octet().unwrap(), Some(b'e'));
        assert_eq!(reader.position, Position { line: 1, column: 3 });
    }

    #[test]
    fn read_field_octet_works_negatively() {
        for data in [b" ".as_slice(), b"".as_slice()] {
            let mut reader = make_reader(data);
            assert_eq!(reader.read_field_octet().unwrap(), None);
            assert_eq!(reader.position, Position { line: 1, column: 1 });
        }
    }

    #[test]
    fn skip_whitespace_works_positively() {
        let mut reader = make_reader(b"  \t \t field");
        assert!(reader.skip_whitespace().unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 7 });
        assert!(reader.expect_field(b"field").unwrap());
    }

    #[test]
    fn skip_whitespace_works_negatively() {
        let mut reader = make_reader(b"field");
        assert!(!reader.skip_whitespace().unwrap());
        assert_eq!(reader.position, Position { line: 1, column: 1 });
    }

    #[test]
    fn skip_whitespace_stops_at_newlines() {
        assert!(!make_reader(b"\n").skip_whitespace().unwrap());
    }

    #[test]
    fn skip_to_eol_works() {
        // We make sure to check that a lone \r is not counted as a line
        // ending.
        let mut reader = make_reader(b"abc\nd\re\r\nf");
        reader.skip_to_eol().unwrap();
        assert_eq!(reader.peek(7).unwrap(), Some(b"\nd\re\r\nf".as_slice()));
        assert_eq!(reader.position, Position { line: 1, column: 4 });
        reader.read_octet().unwrap();
        reader.skip_to_eol().unwrap();
        assert_eq!(reader.peek(3).unwrap(), Some(b"\r\nf".as_slice()));
        assert_eq!(reader.position, Position { line: 2, column: 4 });
    }

    #[test]
    fn skip_through_eol_works() {
        // This is like above, except that we expect to go through the
        // line ending.
        let mut reader = make_reader(b"abc\nd\re\r\nf");
        reader.skip_through_eol().unwrap();
        assert_eq!(reader.peek(6).unwrap(), Some(b"d\re\r\nf".as_slice()));
        assert_eq!(reader.position, Position { line: 2, column: 1 });
        reader.skip_through_eol().unwrap();
        assert_eq!(reader.peek_octet().unwrap(), Some(b'f'));
        assert_eq!(reader.position, Position { line: 3, column: 1 });
    }

    #[test]
    fn skip_to_next_field_or_through_eol_works_skipping_to_field() {
        let mut reader = make_reader(b"      test\n");
        assert_eq!(
            reader.skip_to_next_field_or_through_eol().unwrap(),
            FieldOrEol::Field,
        );
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_to_eol_works_skipping_to_field() {
        let mut reader = make_reader(b"      test\n");
        assert_eq!(
            reader.skip_to_next_field_or_to_eol().unwrap(),
            FieldOrEol::Field,
        );
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_through_eol_works_skipping_through_eol() {
        let mut reader = make_reader(b"      \ntest1  \r\ntest2");
        assert_eq!(
            reader.skip_to_next_field_or_through_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert!(reader.expect_field(b"test1").unwrap());
        assert_eq!(
            reader.skip_to_next_field_or_through_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert!(reader.expect_field(b"test2").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_to_eol_works_skipping_to_eol() {
        let mut reader = make_reader(b"      \ntest1  \r\ntest2");
        assert_eq!(
            reader.skip_to_next_field_or_to_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert_eq!(reader.read_octet().unwrap(), Some(b'\n'));
        assert!(reader.expect_field(b"test1").unwrap());
        assert_eq!(
            reader.skip_to_next_field_or_to_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert_eq!(reader.read_octet().unwrap(), Some(b'\r'));
        assert_eq!(reader.read_octet().unwrap(), Some(b'\n'));
        assert!(reader.expect_field(b"test2").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_through_eol_ignores_comments() {
        let mut reader = make_reader(b"     ; This is a comment\ntest");
        assert_eq!(
            reader.skip_to_next_field_or_through_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_to_eol_ignores_comments() {
        let mut reader = make_reader(b"     ; This is a comment\ntest");
        assert_eq!(
            reader.skip_to_next_field_or_to_eol().unwrap(),
            FieldOrEol::Eol,
        );
        assert_eq!(reader.read_octet().unwrap(), Some(b'\n'));
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_through_eol_processes_parens() {
        let mut reader = make_reader(b"  (\n\r\n; This is a comment\r\n  test)");
        assert_eq!(
            reader.skip_to_next_field_or_through_eol().unwrap(),
            FieldOrEol::Field,
        );
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn skip_to_next_field_or_to_eol_processes_parens() {
        let mut reader = make_reader(b"  (\n\r\n  test)");
        assert_eq!(
            reader.skip_to_next_field_or_to_eol().unwrap(),
            FieldOrEol::Field,
        );
        assert!(reader.expect_field(b"test").unwrap());
    }

    #[test]
    fn field_or_eol_skipping_impl_rejects_unclosed_parens() {
        let mut reader = make_reader(b"(");
        assert!(matches!(
            reader.field_or_eol_skipping_impl(true),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::EofBeforeCloseParen,
        ));
    }

    #[test]
    fn field_or_eol_skipping_impl_rejects_unmatched_close_parens() {
        let mut reader = make_reader(b")");
        assert!(matches!(
            reader.field_or_eol_skipping_impl(true),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::UnmatchedCloseParen,
        ));
    }
}
