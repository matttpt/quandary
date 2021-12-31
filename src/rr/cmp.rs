// Copyright 2021 Matthew Ingwersen.
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

//! Implementation of equality for [`Rdata`].
//!
//! [RFC 3597 § 6] specifies that RRs of unknown type are equal when
//! their RDATA is bitwise equal, and that new RR types should not have
//! type-specific comparison rules. This means that embedded domain
//! names are henceforth compared in a case-sensitive manner! Therefore,
//! only types that (1) predate the RFC and (2) embed domain names need
//! to have special comparison logic.
//!
//! The [`Rdata::equals`] method, implemented in this module, compares
//! RDATA, performing case-insensitive comparison of domain names only
//! in RR types that are old enough to require this.
//!
//! [RFC 3597 § 6]: https://datatracker.ietf.org/doc/html/rfc3597#section-6
//! [RFC 3597 § 7]: https://datatracker.ietf.org/doc/html/rfc3597#section-7

use super::{Rdata, Type};
use crate::name::Name;

impl Rdata {
    /// Compares this [`Rdata`] to another, assuming that they are both
    /// of type `rr_type`. This implements special logic for types
    /// introduced before RFC 3597 that contain domain names, in which
    /// the domain names must be compared case-insensitively.
    /// [RFC 3597 § 6] stipulated that all RDATA should henceforth be
    /// compared bitwise, and thus a bitwise comparison is used for all
    /// later types.
    ///
    /// If, in the process of comparing domain names case-insensitively,
    /// one of the [`Rdata`]s is found to be invalid, this falls back to
    /// a bitwise comparison of the entire [`Rdata`]s.
    ///
    /// [RFC 3597 § 6]: https://datatracker.ietf.org/doc/html/rfc3597#section-6
    pub fn equals(&self, other: &Self, rr_type: Type) -> bool {
        if self.octets().len() != other.octets().len() {
            // Since equal embedded domain names are always the same
            // length (even if they contain octets of differing ASCII
            // case), the RDATAs can't be equal if they have differing
            // lengths.
            false
        } else {
            match rr_type {
                Type::NS
                | Type::MD
                | Type::MF
                | Type::CNAME
                | Type::MB
                | Type::MG
                | Type::MR
                | Type::PTR => names_equal(self, other),
                Type::SOA => soas_equal(self, other),
                Type::MINFO => minfos_equal(self, other),
                Type::MX => mxs_equal(self, other),
                _ => self.octets() == other.octets(),
            }
        }
    }
}

/// Tests two uncompressed on-the-wire names for equality, falling back
/// to bitwise comparison if either is invalid.
fn names_equal(first: &[u8], second: &[u8]) -> bool {
    match test_n_name_fields(first, second, 1) {
        Some(Some(len)) if len == first.len() => true,
        Some(Some(_)) => first == second, // Invalid since there's extra data
        Some(None) => false,
        None => first == second,
    }
}

/// Tests two on-the-wire SOA records *with the same length* for
/// equality, falling back to bitwise comparison if either is invalid.
fn soas_equal(first: &[u8], second: &[u8]) -> bool {
    assert!(first.len() == second.len());
    match test_n_name_fields(first, second, 2) {
        Some(Some(len)) => {
            if first.len() - len != 20 {
                // The remaining fields are not the right length.
                // Fall back to bitwise comparison.
                first == second
            } else {
                // Compare the remaining fields bitwise.
                first[len..] == second[len..]
            }
        }
        Some(None) => false,
        None => first == second,
    }
}

/// Tests two on-the-wire MINFO records for equality, falling back to
/// bitwise comparison if either is invalid.
fn minfos_equal(first: &[u8], second: &[u8]) -> bool {
    match test_n_name_fields(first, second, 2) {
        Some(Some(len)) if len == first.len() => true,
        Some(Some(_)) => first == second, // Invalid since there's extra data
        Some(None) => false,
        None => first == second,
    }
}

/// Tests two on-the-wire MX records *with the same length* for
/// equality. If either contains an invalid domain name, this falls back
/// to bitwise comparison.
fn mxs_equal(first: &[u8], second: &[u8]) -> bool {
    assert!(first.len() == second.len());
    if first.len() > 2 {
        // Note that if names_equal falls back to bitwise comparison,
        // then we did a bitwise comparison of the whole thing, so we
        // still did what we said we would!
        first[0..2] == second[0..2] && names_equal(&first[2..], &second[2..])
    } else {
        // Invalid records; do a bitwise comparison.
        first == second
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
fn test_n_name_fields(first: &[u8], second: &[u8], n: usize) -> Option<Option<usize>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    // The *_equal routines all have very similar and straightforward
    // comparison logic. Since names_equal function is something of a
    // baseline, so we test it here.

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
