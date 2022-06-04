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

//! Handling of the [RFC 3596] RR type, AAAA.
//!
//! [RFC 3596]: https://datatracker.ietf.org/doc/html/rfc3596

use std::net::Ipv6Addr;

use super::{Rdata, ReadRdataError};

////////////////////////////////////////////////////////////////////////
// RFC 3596 §§ 2.1 and 2.2 - IPV6 AAAA RR                             //
////////////////////////////////////////////////////////////////////////

/// Serializes an AAAA record into the provided buffer.
pub fn serialize_aaaa(address: Ipv6Addr, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&address.octets());
}

impl Rdata {
    /// Validates this [`Rdata`] for correctness, assuming that it is of
    /// type AAAA.
    pub fn validate_as_aaaa(&self) -> Result<(), ReadRdataError> {
        if self.len() == 16 {
            Ok(())
        } else {
            Err(ReadRdataError::Other)
        }
    }
}
