// Copyright 2021 Matthew Ingwersen.
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

//! [`Debug`](fmt::Debug) and [`Display`](fmt::Display) implementations
//! for RR-related types.

use std::fmt::{self, Write};

use super::{Rdata, Rrset};
use crate::util::nibble_to_ascii_hex_digit;

///////////////////////////////////////////////////////////////////////
// RRSET DEBUGGING                                                   //
///////////////////////////////////////////////////////////////////////

impl fmt::Debug for Rrset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Rrset")
            .field("rr_type", &self.rr_type)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("rdatas", &RdatasDebugger(self))
            .finish()
    }
}

struct RdatasDebugger<'a>(&'a Rrset);

impl fmt::Debug for RdatasDebugger<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut list = f.debug_list();
        for rdata in self.0.rdatas() {
            list.entry(&format_args!("{:?}", rdata));
        }
        list.finish()
    }
}

///////////////////////////////////////////////////////////////////////
// RDATA DISPLAYING AND DEBUGGING                                    //
///////////////////////////////////////////////////////////////////////

impl fmt::Display for Rdata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // We output using the RFC 3597 format for RDATA of unknown
        // type.
        write!(f, "\\# {}", self.len())?;
        if !self.is_empty() {
            f.write_char(' ')?;
            for octet in self.iter() {
                f.write_char(char::from(nibble_to_ascii_hex_digit((octet & 0xf0) >> 4)))?;
                f.write_char(char::from(nibble_to_ascii_hex_digit(octet & 0xf)))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Rdata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}
