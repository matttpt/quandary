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

//! Implementation of the [`Error`] type for zone-related errors.

use std::fmt;

use crate::rr::rrset::RrsetListAddError;

/// Errors that arise during operations on a [`Zone`](super::Zone).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    NotInZone,
    ClassMismatch,
    TtlMismatch,
    RdataTooLong,
    InvalidRdata,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::NotInZone => f.write_str("the record's owner is not within the zone"),
            Self::ClassMismatch => {
                f.write_str("the record's class does not match the zone's class")
            }
            Self::TtlMismatch => f.write_str(
                "the record's TTL does not match the TTL of existing records in the same RRset",
            ),
            Self::RdataTooLong => f.write_str("RDATA was longer than 65,536 octets"),
            Self::InvalidRdata => {
                f.write_str("the operation required RDATA parsing, and invalid RDATA was found")
            }
        }
    }
}

impl From<RrsetListAddError> for Error {
    fn from(error: RrsetListAddError) -> Self {
        match error {
            RrsetListAddError::ClassMismatch => Self::ClassMismatch,
            RrsetListAddError::TtlMismatch => Self::TtlMismatch,
        }
    }
}

impl std::error::Error for Error {}
