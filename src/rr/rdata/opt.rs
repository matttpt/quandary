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

//! Helpers for the EDNS pseudo-RR type, OPT.
//!
//! This follows EDNS(0) as restated and refined by [RFC 6891].
//!
//! [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891

use super::{Rdata, RdataTooLongError, ReadRdataError};

////////////////////////////////////////////////////////////////////////
// EDNS(0) (RFC 6891) - OPT PSEUDO-RR                                 //
////////////////////////////////////////////////////////////////////////

/// A helper to serialize EDNS OPT record RDATA.
///
/// [RFC 6891 § 6.1.2] defines the wire format for OPT RDATA. It
/// consists of attribute-value pairs to specify EDNS options. This
/// helper allows one to easily serialize this record type's RDATA; it
/// functions very similarly to the [`TxtBuilder`](super::TxtBuilder)
/// utility. See the analogous documentation and example there.
///
/// [RFC 6891 § 6.1.2]: https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
pub struct OptBuilder<'a> {
    buf: &'a mut Vec<u8>,
    octets_written: usize,
}

impl<'a> OptBuilder<'a> {
    /// Constructs a new `OptBuilder` that will serialize EDNS options
    /// into the provided buffer.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self {
            buf,
            octets_written: 0,
        }
    }

    /// Attempts to serialize an additional EDNS option into the
    /// underlying buffer. If this would exceed the maximum RDATA length
    /// of 65,535 octets, then this will fail.
    pub fn try_push(&mut self, code: u16, data: &[u8]) -> Result<(), RdataTooLongError> {
        if self.octets_written + 4 + data.len() > (u16::MAX as usize) {
            Err(RdataTooLongError)
        } else {
            self.buf.reserve(4 + data.len());
            self.buf.extend_from_slice(&code.to_be_bytes());
            self.buf
                .extend_from_slice(&(data.len() as u16).to_be_bytes());
            self.buf.extend_from_slice(data);
            self.octets_written += 4 + data.len();
            Ok(())
        }
    }
}

impl Rdata {
    /// Validates this [`Rdata`] for correctness, assuming that it is of
    /// type OPT.
    pub fn validate_as_opt(&self) -> Result<(), ReadRdataError> {
        let mut offset = 0;
        while offset < self.len() {
            offset += validate_option(&self.octets[offset..])?;
        }
        Ok(())
    }
}

/// Validates a single option in an OPT record's RDATA.
fn validate_option(octets: &[u8]) -> Result<usize, ReadRdataError> {
    if let Some(len_octets) = octets.get(2..4) {
        let len = u16::from_be_bytes([len_octets[0], len_octets[1]]) as usize;
        if octets.len() >= len + 4 {
            Ok(len + 4)
        } else {
            Err(ReadRdataError::Other)
        }
    } else {
        Err(ReadRdataError::Other)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optbuilder_works() {
        let mut rdata = Vec::new();
        let mut builder = OptBuilder::new(&mut rdata);
        builder.try_push(12, &[0; 4]).unwrap(); // Padding: RFC 7830
        builder.try_push(9, &[]).unwrap(); // EXPIRE: RFC 7314
        assert_eq!(rdata, b"\x00\x0c\x00\x04\x00\x00\x00\x00\x00\x09\x00\x00");
    }

    #[test]
    fn optbuilder_rejects_rdata_overflow() {
        let mut rdata = Vec::new();
        let mut builder = OptBuilder::new(&mut rdata);
        for _ in 0..255 {
            builder.try_push(0, &[0; 252]).unwrap();
        }
        assert_eq!(builder.try_push(0, &[0; 252]), Err(RdataTooLongError));
    }
}
