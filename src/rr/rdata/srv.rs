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

//! Handling of the [RFC 2782] RR type, SRV.
//!
//! [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782

use super::helpers;
use super::{ComponentType, Components, Rdata, ReadRdataError};
use crate::name::Name;

////////////////////////////////////////////////////////////////////////
// RFC 2782 - SRV RR                                                  //
////////////////////////////////////////////////////////////////////////

/// Serializes an SRV record into the provided buffer.
pub fn serialize_srv(priority: u16, weight: u16, port: u16, target: &Name, buf: &mut Vec<u8>) {
    buf.reserve(6 + target.wire_repr().len());
    buf.extend_from_slice(&priority.to_be_bytes());
    buf.extend_from_slice(&weight.to_be_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(target.wire_repr());
}

impl Rdata {
    /// Serializes an SRV record into a new boxed [`Rdata`].
    pub fn new_srv(priority: u16, weight: u16, port: u16, target: &Name) -> Box<Self> {
        let mut buf = Vec::with_capacity(6 + target.wire_repr().len());
        serialize_srv(priority, weight, port, target, &mut buf);
        buf.try_into().unwrap()
    }

    /// Validates this [`Rdata`] for correctness, assuming that it is of
    /// type SRV.
    pub fn validate_as_srv(&self) -> Result<(), ReadRdataError> {
        if let Some(name_octets) = self.octets.get(6..) {
            Name::validate_uncompressed_all(name_octets).map_err(Into::into)
        } else {
            Err(ReadRdataError::Other)
        }
    }

    /// Reads SRV RDATA from a message. See [`Rdata::read`] for details.
    pub fn read_srv(
        message: &[u8],
        cursor: usize,
        rdlength: u16,
    ) -> Result<Box<Self>, ReadRdataError> {
        let buf = helpers::prepare_to_read_rdata(message, cursor, rdlength)?;
        if buf.len() - cursor < 6 {
            Err(ReadRdataError::Other)
        } else {
            let (exchange, len) = Name::try_from_compressed(buf, cursor + 6)?;
            if buf.len() - cursor != len + 6 {
                Err(ReadRdataError::Other)
            } else {
                let mut rdata = Vec::with_capacity(6 + exchange.wire_repr().len());
                rdata.extend_from_slice(&buf[cursor..cursor + 6]);
                rdata.extend_from_slice(exchange.wire_repr());
                Ok(rdata.try_into().unwrap())
            }
        }
    }

    /// Determines whether this [`Rdata`] is equal to another, assuming
    /// that both are of type SRV. See [`Rdata::equals`] for details.
    pub fn equals_as_srv(&self, other: &Rdata) -> bool {
        if self.len() != other.len() {
            false
        } else if self.len() > 6 {
            // Note that if names_equal falls back to bitwise comparison,
            // then we did a bitwise comparison of the whole thing, so we
            // still did what we said we would!
            self.octets[0..6] == other.octets[0..6]
                && helpers::names_equal(&self.octets[6..], &other.octets[6..])
        } else {
            // Invalid records; do a bitwise comparison.
            self.octets == other.octets
        }
    }

    /// Returns an iterator over this `Rdata`'s
    /// [`Component`](super::Component)s, assuming that it is of type
    /// SRV.
    pub fn components_as_srv(&self) -> Components {
        Components {
            types: &[
                ComponentType::FixedLen(6),
                ComponentType::UncompressibleName,
            ],
            rdata: self.octets(),
        }
    }
}
