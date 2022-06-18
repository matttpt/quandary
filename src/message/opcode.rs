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

//! Implementation of the [`Opcode`] type.

use std::fmt;

////////////////////////////////////////////////////////////////////////
// OPCODES                                                            //
////////////////////////////////////////////////////////////////////////

/// The opcode value of the DNS message header.
///
/// [RFC 1035 § 4.1.1] defines the opcode field as a four-bit field
/// indicating the kind of query being made in the message. The first
/// three values are from the original specification, while the rest
/// have been added in later extensions to the DNS.
///
/// [RFC 1035 § 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct Opcode(u8);

impl Opcode {
    pub const QUERY: Self = Self(0);
    pub const IQUERY: Self = Self(1);
    pub const STATUS: Self = Self(2);
    pub const NOTIFY: Self = Self(4);
    pub const UPDATE: Self = Self(5);
    pub const DSO: Self = Self(6);
}

impl TryFrom<u8> for Opcode {
    type Error = IntoOpcodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < 16 {
            Ok(Self(value))
        } else {
            Err(IntoOpcodeError)
        }
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        value.0
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::QUERY => f.write_str("QUERY"),
            Self::IQUERY => f.write_str("IQUERY"),
            Self::STATUS => f.write_str("STATUS"),
            Self::NOTIFY => f.write_str("NOTIFY"),
            Self::UPDATE => f.write_str("UPDATE"),
            Self::DSO => f.write_str("DSO"),
            Self(value) => write!(f, "unassigned opcode {}", value),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error signaling that the provided value is not a valid opcode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IntoOpcodeError;

impl fmt::Display for IntoOpcodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("not a valid opcode")
    }
}

impl std::error::Error for IntoOpcodeError {}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_try_from_u8_accepts_valid_values() {
        for value in 0..16 {
            assert_eq!(Opcode::try_from(value), Ok(Opcode(value)));
        }
    }

    #[test]
    fn opcode_try_from_u8_rejects_large_values() {
        for value in 16..=u8::MAX {
            assert_eq!(Opcode::try_from(value), Err(IntoOpcodeError));
        }
    }
}
