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

//! Implementation of helpers for the [RFC 2782] RR type, SRV.
//!
//! [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782

use super::Rdata;
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
pub fn is_valid_srv(rdata: &Rdata) -> bool {
    rdata
        .get(6..)
        .map(Name::validate_uncompressed_all)
        .map(Result::ok)
        .flatten()
        .is_some()
}
