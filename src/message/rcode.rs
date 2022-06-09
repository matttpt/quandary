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

//! Implementation of the [`Rcode`] type.

use std::fmt;

////////////////////////////////////////////////////////////////////////
// RCODES                                                             //
////////////////////////////////////////////////////////////////////////

/// The RCODE value of the DNS message header.
///
/// [RFC 1035 § 4.1.1] defines the RCODE field as a four-bit field
/// indicating success or failure in a DNS response. The first six
/// values are original to RFC 1035, while the rest have been added in
/// subsequent extensions of the DNS.
///
/// EDNS(0) introduced extended RCODEs via the OPT pseudo-RR; these are
/// not implemented by this type.
///
/// [RFC 1035 § 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct Rcode(u8);

impl Rcode {
    pub const NOERROR: Self = Self(0);
    pub const FORMERR: Self = Self(1);
    pub const SERVFAIL: Self = Self(2);
    pub const NXDOMAIN: Self = Self(3);
    pub const NOTIMP: Self = Self(4);
    pub const REFUSED: Self = Self(5);
    pub const YXDOMAIN: Self = Self(6);
    pub const YXRRSET: Self = Self(7);
    pub const NXRRSET: Self = Self(8);
    pub const NOTAUTH: Self = Self(9);
    pub const NOTZONE: Self = Self(10);
    pub const DSOTYPENI: Self = Self(11);
}

impl TryFrom<u8> for Rcode {
    type Error = IntoRcodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < 16 {
            Ok(Self(value))
        } else {
            Err(IntoRcodeError)
        }
    }
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> Self {
        value.0
    }
}

impl fmt::Debug for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::NOERROR => f.write_str("NOERROR"),
            Self::FORMERR => f.write_str("FORMERR"),
            Self::SERVFAIL => f.write_str("SERVFAIL"),
            Self::NXDOMAIN => f.write_str("NXDOMAIN"),
            Self::NOTIMP => f.write_str("NOTIMP"),
            Self::REFUSED => f.write_str("REFUSED"),
            Self::YXDOMAIN => f.write_str("YXDOMAIN"),
            Self::YXRRSET => f.write_str("YXRRSET"),
            Self::NXRRSET => f.write_str("NXRRSET"),
            Self::NOTAUTH => f.write_str("NOTAUTH"),
            Self::NOTZONE => f.write_str("NOTZONE"),
            Self::DSOTYPENI => f.write_str("DSOTYPENI"),
            Self(value) => write!(f, "unassigned RCODE {}", value),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error signaling that the provided value is not a valid RCODE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntoRcodeError;

impl fmt::Display for IntoRcodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("not a valid RCODE")
    }
}

impl std::error::Error for IntoRcodeError {}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcode_constructor_accepts_valid_values() {
        for value in 0..16 {
            assert_eq!(Rcode::try_from(value), Ok(Rcode(value)));
        }
    }

    #[test]
    fn rcode_constructor_rejects_large_values() {
        for value in 16..=u8::MAX {
            assert_eq!(Rcode::try_from(value), Err(IntoRcodeError));
        }
    }
}
