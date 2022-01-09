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
/// have been added in later extensions to the DNS. The names of each
/// member of the `Opcode` enumeration are those listed by the IANA.
///
/// [RFC 1035 § 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Dso,
    Unassigned(u8),
}

impl TryFrom<u8> for Opcode {
    type Error = IntoOpcodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::IQuery),
            2 => Ok(Self::Status),
            4 => Ok(Self::Notify),
            5 => Ok(Self::Update),
            6 => Ok(Self::Dso),
            3 | 7..=15 => Ok(Self::Unassigned(value)),
            _ => Err(IntoOpcodeError),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Dso => 6,
            Opcode::Unassigned(v) => v,
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
