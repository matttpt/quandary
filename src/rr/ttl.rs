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

//! Provides the [`Ttl`] structure for DNS RR TTLs.

use std::fmt;

////////////////////////////////////////////////////////////////////////
// TTLS                                                               //
////////////////////////////////////////////////////////////////////////

/// The time to live (TTL) of a DNS record.
///
/// There are contradictory definitions of the TTL field in [RFC 1035]
/// (see [erratum 2130]), so [RFC 2181 § 8] clarified that TTL values
/// are unsigned integers between 0 and 2³¹ - 1, inclusive. Because the
/// TTL field is 32 bits wide, the most significant bit is zero. A TTL
/// value received with the most significant bit set is interpreted as
/// zero.
///
/// This type wraps `u32` to implement [RFC 2181 § 8]. The public API
/// will only instantiate `Ttl` objects whose underlying `u32` values
/// have the most significant bit set to zero, and `Ttl::from(u32)`
/// treats TTL wire values with the most significant bit set as zero.
///
/// [Erratum 2130]: https://www.rfc-editor.org/errata/eid2130
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 2181 § 8]: https://datatracker.ietf.org/doc/html/rfc2181#section-8
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ttl(u32);

impl From<u32> for Ttl {
    fn from(raw: u32) -> Self {
        if raw > i32::MAX as u32 {
            Self(0)
        } else {
            Self(raw)
        }
    }
}

impl From<Ttl> for u32 {
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

impl fmt::Debug for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_ttls_are_not_modified() {
        let i32_max = i32::MAX as u32;
        assert_eq!(u32::from(Ttl::from(0)), 0);
        assert_eq!(u32::from(Ttl::from(23)), 23);
        assert_eq!(u32::from(Ttl::from(i32_max)), i32_max);
    }

    #[test]
    fn large_ttls_become_zero() {
        assert_eq!(u32::from(Ttl::from(i32::MAX as u32 + 1)), 0);
    }
}
