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

//! Crate-private utilities.

/// A wrapper around [`str`] references whose [`PartialEq`] and [`Eq`]
/// implementations are ASCII-case-insensitive.
pub struct Caseless<'a>(pub &'a str);

impl PartialEq for Caseless<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for Caseless<'_> {}

/// Converts a nibble into an ASCII hex character. Lower-case hex digits
/// are used. The passed value must be less than 16.
pub fn nibble_to_ascii_hex_digit(nibble: u8) -> u8 {
    assert!(nibble < 16);
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    }
}