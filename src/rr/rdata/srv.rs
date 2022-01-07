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

//! Helpers for the [RFC 2782] RR type, SRV.
//!
//! [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782

use super::helpers;
use super::{Rdata, ReadRdataError};
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

/// Checks whether `rdata` is a valid serialized SRV record.
pub(crate) fn validate_srv(rdata: &Rdata) -> Result<(), ReadRdataError> {
    if let Some(name_octets) = rdata.get(6..) {
        Name::validate_uncompressed_all(name_octets).map_err(Into::into)
    } else {
        Err(ReadRdataError::Other)
    }
}

/// Validates and decompresses an SRV record. This is for the
/// implementation of [`Rdata::read`].
pub(super) fn read_srv(buf: &[u8], cursor: usize) -> Result<Box<Rdata>, ReadRdataError> {
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

/// Tests two on-the-wire SRV records *with the same length* for
/// equality. If either contains an invalid domain name, then this falls
/// back to bitwise comparison.
pub(crate) fn srvs_equal(first: &Rdata, second: &Rdata) -> bool {
    assert!(first.len() == second.len());
    if first.len() > 6 {
        // Note that if names_equal falls back to bitwise comparison,
        // then we did a bitwise comparison of the whole thing, so we
        // still did what we said we would!
        first[0..6] == second[0..6] && helpers::names_equal(&first[6..], &second[6..])
    } else {
        // Invalid records; do a bitwise comparison.
        first == second
    }
}
