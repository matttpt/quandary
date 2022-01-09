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
/// subsequent extensions of the DNS. The names given to each member of
/// the `Rcode` enumeration are those listed by the IANA.
///
/// EDNS(0) introduced extended RCODEs via the OPT pseudo-RR; these are
/// not implemented by this type.
///
/// [RFC 1035 § 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrset,
    NxRrset,
    NotAuth,
    NotZone,
    DsoTypeNi,
    Unassigned(u8),
}

impl TryFrom<u8> for Rcode {
    type Error = IntoRcodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoError),
            1 => Ok(Self::FormErr),
            2 => Ok(Self::ServFail),
            3 => Ok(Self::NxDomain),
            4 => Ok(Self::NotImp),
            5 => Ok(Self::Refused),
            6 => Ok(Self::YxDomain),
            7 => Ok(Self::YxRrset),
            8 => Ok(Self::NxRrset),
            9 => Ok(Self::NotAuth),
            10 => Ok(Self::NotZone),
            11 => Ok(Self::DsoTypeNi),
            12..=15 => Ok(Self::Unassigned(value)),
            _ => Err(IntoRcodeError),
        }
    }
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> Self {
        match value {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::YxDomain => 6,
            Rcode::YxRrset => 7,
            Rcode::NxRrset => 8,
            Rcode::NotAuth => 9,
            Rcode::NotZone => 10,
            Rcode::DsoTypeNi => 11,
            Rcode::Unassigned(v) => v,
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
