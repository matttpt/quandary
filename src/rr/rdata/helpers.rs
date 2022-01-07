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

//! Helpers for the [`Rdata::equals`](super::Rdata::equals) and
//! [`Rdata::validate`](super::Rdata::validate) methods, and their
//! RR type-specific implementations.

use super::{Rdata, ReadRdataError};
use crate::name::Name;

////////////////////////////////////////////////////////////////////////
// HELPERS FOR Rdata::equals AND TYPE-SPECIFIC IMPLEMENTATIONS        //
////////////////////////////////////////////////////////////////////////

/// Tests two uncompressed on-the-wire names for equality, falling back
/// to bitwise comparison if either is invalid.
pub fn names_equal(first: &[u8], second: &[u8]) -> bool {
    match test_n_name_fields(first, second, 1) {
        Some(Some(len)) if len == first.len() => true,
        Some(Some(_)) => first == second, // Invalid since there's extra data
        Some(None) => false,
        None => first == second,
    }
}

/// Tests `n` consecutive name fields for equality, starting at the
/// beginning of each buffer. Since the comparison logic in this module
/// promises to fall back to bitwise comparison if invalid data is
/// encountered, we have to be careful how we do things. If we have
/// already checked that the first `m` name fields are equal as domain
/// names (case-insensitively), and then we encounter an invalid domain
/// name, then everything must be re-compared bitwise, including the
/// first `m` name fields. To faciliate this, this function returns the
/// following:
///
/// * `Some(Some(len))` if all the fields were valid and equal when
///   compared case-insensitively; `len` is the total length of the `n`
///   fields.
/// * `Some(None)` if we can definitively say that the answer should be
///   `false` with no further (re-)comparison.
/// * `None` if, due to an invalid domain name, we can't make a
///   a decision without re-comparing everything bitwise.
pub fn test_n_name_fields(first: &[u8], second: &[u8], n: usize) -> Option<Option<usize>> {
    let mut offset = 0;
    for _ in 0..n {
        // At this point: all previous fields were valid names and equal
        // by case-insensitive comparison. Let's try to do the next
        // field.
        match (
            Name::try_from_uncompressed(&first[offset..]),
            Name::try_from_uncompressed(&second[offset..]),
        ) {
            (Err(_), Err(_)) => {
                // Both are invalid. The caller should fall back to
                // bitwise comparison, including the names we have
                // already checked case-insensitively.
                return None;
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                // Like above, the caller should fall back to bitwise
                // comparison. But actually, there's a shortcut. Because
                // one was valid and the other wasn't, there's no way
                // that these can be bitwise equal.
                return Some(None);
            }
            (Ok((first_fieldn, fieldn_len)), Ok((second_fieldn, _))) => {
                if first_fieldn == second_fieldn {
                    offset += fieldn_len;
                    // ... and we continue with the next field.
                } else {
                    // If they are not equal case-insensitively, then
                    // _a fortiori_ they are not bitwise equal.
                    return Some(None);
                }
            }
        }
    }

    // All the fields are valid and equal!
    Some(Some(offset))
}

////////////////////////////////////////////////////////////////////////
// HELPER FOR Rdata::validate                                         //
////////////////////////////////////////////////////////////////////////

/// Checks whether `name` is a valid seralized domain name. This is for
/// the implementation of [`Rdata::validate`].
pub fn validate_name(name: &[u8]) -> Result<(), ReadRdataError> {
    Name::validate_uncompressed_all(name).map_err(Into::into)
}

////////////////////////////////////////////////////////////////////////
// HELPER FOR Rdata::read                                             //
////////////////////////////////////////////////////////////////////////

/// Validates and decompresses RDATA consisting of a single domain name.
/// This is for the implementation of [`Rdata::read`].
pub fn read_name_rdata(buf: &[u8], cursor: usize) -> Result<Box<Rdata>, ReadRdataError> {
    let (name, len) = Name::try_from_compressed(buf, cursor)?;
    if buf.len() - cursor != len {
        Err(ReadRdataError::Other)
    } else {
        Ok(<&Rdata>::try_from(name.wire_repr()).unwrap().to_owned())
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names_compare_case_insensitively() {
        let name_a = b"\x08quandary\x04test\x00";
        let name_b = b"\x08Quandary\x04TEST\x00";
        assert!(names_equal(name_a, name_b));
    }

    #[test]
    fn invalid_names_compare_bitwise() {
        let name_a_and_junk = b"\x08quandary\x04test\x00junk";
        let name_b_and_junk = b"\x00Quandary\x04TEST\x00junk";
        assert!(!names_equal(name_a_and_junk, name_b_and_junk));

        let invalid_a = b"\x07quandary\x04test\x00";
        let invalid_b = b"\x07Quandary\x04TEST\x00";
        assert!(!names_equal(invalid_a, invalid_b));
    }

    #[test]
    fn test_n_name_fields_is_positive_when_both_are_valid_and_equal() {
        assert_eq!(
            test_n_name_fields(
                b"\x04test\x00\x07EXAMPLE\x00\x04test\x00junk",
                b"\x04test\x00\x07EXAMPLE\x00\x04test\x00",
                2
            ),
            Some(Some(15)),
        );
    }

    #[test]
    fn test_n_name_fields_is_negative_when_both_are_valid_and_not_equal() {
        assert_eq!(
            test_n_name_fields(
                b"\x04test\x00\x07EXAMPLE\x00",
                b"\x07example\x00\x04test\x00",
                2
            ),
            Some(None),
        );
    }

    #[test]
    fn test_n_name_fields_is_negative_when_only_one_is_valid() {
        assert_eq!(
            test_n_name_fields(
                b"\x04test\x00\x07EXAMPLE\x00",
                b"\x04test\xff\x07EXAMPLE\x00",
                2
            ),
            Some(None),
        );
        assert_eq!(
            test_n_name_fields(b"\x07invalid", b"\x04test\x00\x07example\x00", 2),
            Some(None),
        );
    }

    #[test]
    fn test_n_name_fields_is_inconclusive_for_both_invalid() {
        assert_eq!(
            test_n_name_fields(b"\x04test\x00", b"\x04Test\x00", 2),
            None
        );
        assert_eq!(
            test_n_name_fields(b"\x04test\x00\xffjunk", b"\x04Test\x00\x03jun\xff", 2),
            None
        );
    }
}
