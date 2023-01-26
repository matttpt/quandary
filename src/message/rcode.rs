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

//! Implementation of the [`Rcode`] and [`ExtendedRcode`] types.

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
/// EDNS introduced extended RCODEs via the OPT pseudo-RR, and the TSIG
/// and TKEY meta-RRs have extended RCODE fields that share the same
/// error number space. This is an extension of the original RCODE
/// space. Extended RCODEs are not implemented by this type, but rather
/// by the [`ExtendedRcode`] enumeration.
///
/// The [`From`]/[`Into`]/[`TryFrom`]/[`TryInto`] traits can be used to
/// convert between unextended [`Rcode`]s and [`ExtendedRcode`]s.
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

impl TryFrom<ExtendedRcode> for Rcode {
    type Error = IntoRcodeError;

    fn try_from(value: ExtendedRcode) -> Result<Self, Self::Error> {
        if value.0 < 16 {
            Ok(Self(value.0 as u8))
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
            Self(value) => write!(f, "unassigned RCODE {value}"),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// EXTENDED RCODES                                                    //
////////////////////////////////////////////////////////////////////////

/// The extended RCODE of a DNS message.
///
/// [RFC 6891] allocates 8 bits in the TTL of the EDNS OPT record to
/// extend the 4-bit RCODE field of the DNS header to 12 bits.
/// Furthermore, [RFC 8945] specifies a 16-bit field in the TSIG record
/// for an extended RCODE, as does [RFC 2930] for the TKEY record.
/// [RFC 6895 § 2.3] clarifies that these fields share a unified 16-bit
/// error number space, which extends the original 4-bit RCODE space.
/// This enumeration represents this unified 16-bit space. The names
/// given to each member are those given by the IANA.
///
/// The [`From`]/[`Into`]/[`TryFrom`]/[`TryInto`] traits can be used to
/// convert between unextended [`Rcode`]s and [`ExtendedRcode`]s.
///
/// [RFC 2930]: https://datatracker.ietf.org/doc/html/rfc2930
/// [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891
/// [RFC 6895 § 2.3]: https://datatracker.ietf.org/doc/html/rfc6895#section-2.3
/// [RFC 8945]: https://datatracker.ietf.org/doc/html/rfc8945
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct ExtendedRcode(u16);

impl ExtendedRcode {
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
    pub const BADVERSBADSIG: Self = Self(16);
    pub const BADKEY: Self = Self(17);
    pub const BADTIME: Self = Self(18);
    pub const BADMODE: Self = Self(19);
    pub const BADNAME: Self = Self(20);
    pub const BADALG: Self = Self(21);
    pub const BADTRUNC: Self = Self(22);
    pub const BADCOOKIE: Self = Self(23);
}

impl From<u16> for ExtendedRcode {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Rcode> for ExtendedRcode {
    fn from(value: Rcode) -> Self {
        Self(value.0 as u16)
    }
}

impl From<ExtendedRcode> for u16 {
    fn from(value: ExtendedRcode) -> Self {
        value.0
    }
}

impl fmt::Debug for ExtendedRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl fmt::Display for ExtendedRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Ok(unextended_rcode) = Rcode::try_from(*self) {
            unextended_rcode.fmt(f)
        } else {
            match *self {
                Self::BADVERSBADSIG => f.write_str("BADVERS/BADSIG"),
                Self::BADKEY => f.write_str("BADKEY"),
                Self::BADTIME => f.write_str("BADTIME"),
                Self::BADMODE => f.write_str("BADMODE"),
                Self::BADNAME => f.write_str("BADNAME"),
                Self::BADALG => f.write_str("BADALG"),
                Self::BADTRUNC => f.write_str("BADTRUNC"),
                Self::BADCOOKIE => f.write_str("BADCOOKIE"),
                Self(value) => write!(f, "unassigned extended RCODE {value}"),
            }
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
    fn rcode_try_from_u8_accepts_valid_values() {
        for value in 0..16 {
            assert_eq!(Rcode::try_from(value), Ok(Rcode(value)));
        }
    }

    #[test]
    fn rcode_try_from_u8_rejects_large_values() {
        for value in 16..=u8::MAX {
            assert_eq!(Rcode::try_from(value), Err(IntoRcodeError));
        }
    }

    #[test]
    fn rcode_try_from_extended_rcode_rejects_large_values() {
        for value in 16..=u16::MAX {
            let extended_rcode = ExtendedRcode(value);
            assert_eq!(Rcode::try_from(extended_rcode), Err(IntoRcodeError));
        }
    }
}
