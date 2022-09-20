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

//! Handling of the transaction signature (TSIG) RR type.
//!
//! This follows the specification TSIG specification as restated and
//! updated by [RFC 8945].
//!
//! [RFC 8945]: https://datatracker.ietf.org/doc/html/rfc8945

use super::{Rdata, RdataTooLongError, ReadRdataError};
use crate::message::ExtendedRcode;
use crate::name::Name;

////////////////////////////////////////////////////////////////////////
// RFC 8945 - TSIG PSEUDO-RR                                          //
////////////////////////////////////////////////////////////////////////

/// Serializes a TSIG record into the provided buffer.
///
/// This checks whether the resulting TSIG RDATA would exceed the
/// 65,535-octet limit and returns an error if so.
#[allow(clippy::too_many_arguments)]
pub fn serialize_tsig(
    algorithm: &Name,
    time_signed: [u8; 6],
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: ExtendedRcode,
    other: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), RdataTooLongError> {
    let len = required_len(algorithm, mac, other)?;
    buf.reserve(len);
    serialize_tsig_unchecked(
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
        buf,
    );
    Ok(())
}

/// Serializes a TSIG record into the provided buffer, without checking
/// the resulting length.
#[allow(clippy::too_many_arguments)]
fn serialize_tsig_unchecked(
    algorithm: &Name,
    time_signed: [u8; 6],
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: ExtendedRcode,
    other: &[u8],
    buf: &mut Vec<u8>,
) {
    buf.extend_from_slice(algorithm.wire_repr());
    buf.extend_from_slice(time_signed.as_slice());
    buf.extend_from_slice(&fudge.to_be_bytes());
    buf.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    buf.extend_from_slice(mac);
    buf.extend_from_slice(&original_id.to_be_bytes());
    buf.extend_from_slice(&u16::from(error).to_be_bytes());
    buf.extend_from_slice(&(other.len() as u16).to_be_bytes());
    buf.extend_from_slice(other);
}

/// Returns the size of a TSIG RDATA with the given algorithm, MAC, and
/// other data.
fn required_len(algorithm: &Name, mac: &[u8], other: &[u8]) -> Result<usize, RdataTooLongError> {
    (algorithm.wire_repr().len() + 16)
        .checked_add(mac.len())
        .and_then(|len| len.checked_add(other.len()))
        .filter(|len| *len <= u16::MAX as usize)
        .ok_or(RdataTooLongError)
}

impl Rdata {
    /// Serializes a TSIG record into a new boxed [`Rdata`].
    ///
    /// This checks whether the resulting TSIG RDATA would exceed the
    /// 65,535-octet limit and returns an error if so.
    pub fn new_tsig(
        algorithm: &Name,
        time_signed: [u8; 6],
        fudge: u16,
        mac: &[u8],
        original_id: u16,
        error: ExtendedRcode,
        other: &[u8],
    ) -> Result<Box<Self>, RdataTooLongError> {
        let len = required_len(algorithm, mac, other)?;
        let mut buf = Vec::with_capacity(len);
        serialize_tsig_unchecked(
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
            &mut buf,
        );
        Ok(buf.try_into().unwrap())
    }

    /// Validates this [`Rdata`] for correctness, assuming that it is of
    /// type TSIG.
    ///
    /// Not that this merely checks the [`Rdata`] for correct form. It
    /// does not check whether the algorithm name is defined or whether
    /// the MAC size is acceptable, nor does it perform any
    /// cryptographic operations.
    pub fn validate_as_tsig(&self) -> Result<(), ReadRdataError> {
        let algorithm_len = Name::validate_uncompressed(&self.octets)?;
        let mac_size_octets = self
            .octets
            .get(algorithm_len + 8..algorithm_len + 10)
            .ok_or(ReadRdataError::Other)?;
        let mac_size = u16::from_be_bytes(mac_size_octets.try_into().unwrap()) as usize;
        let other_len_octets = self
            .octets
            .get(algorithm_len + mac_size + 14..algorithm_len + mac_size + 16)
            .ok_or(ReadRdataError::Other)?;
        let other_len = u16::from_be_bytes(other_len_octets.try_into().unwrap()) as usize;
        if algorithm_len + mac_size + other_len + 16 == self.octets.len() {
            Ok(())
        } else {
            Err(ReadRdataError::Other)
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    const TSIG_RDATA: &[u8] = b"\
        \x0b\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x35\x36\x00\x00\x00\x63\
        \x29\x12\xb4\x01\x2c\x00\x20\xfe\x60\x1b\xa4\xb2\x4a\x33\x48\xd3\
        \x47\xe4\x4e\x8e\x02\xdf\x7b\x83\xf1\xee\x38\xea\x05\x3e\xde\xe8\
        \xb0\x8e\x26\x52\x46\xda\xf4\xab\x97\x00\x00\x00\x0f\x73\x6f\x6d\
        \x65\x20\x6f\x74\x68\x65\x72\x20\x64\x61\x74\x61";

    lazy_static! {
        static ref ALGORITHM: Box<Name> = "hmac-sha256.".parse().unwrap();
    }
    const TIME_SIGNED: &[u8; 6] = b"\x00\x00\x63\x29\x12\xb4";
    const FUDGE: u16 = 300;
    const MAC: &[u8] = b"\
        \xfe\x60\x1b\xa4\xb2\x4a\x33\x48\xd3\x47\xe4\x4e\x8e\x02\xdf\x7b\
        \x83\xf1\xee\x38\xea\x05\x3e\xde\xe8\xb0\x8e\x26\x52\x46\xda\xf4";
    const ORIGINAL_ID: u16 = 0xab97;
    const ERROR: ExtendedRcode = ExtendedRcode::NOERROR;
    const OTHER: &[u8] = b"some other data";

    #[test]
    fn serialization_works() {
        let tsig_rdata = Rdata::new_tsig(
            &ALGORITHM,
            *TIME_SIGNED,
            FUDGE,
            MAC,
            ORIGINAL_ID,
            ERROR,
            OTHER,
        )
        .unwrap();
        assert_eq!(tsig_rdata.octets(), TSIG_RDATA);
    }

    #[test]
    fn required_len_works() {
        assert_eq!(
            required_len(&ALGORITHM, MAC, OTHER).unwrap(),
            TSIG_RDATA.len()
        );
    }

    #[test]
    fn serialize_refuses_to_create_long_rdata() {
        let mut buf = Vec::new();
        assert_eq!(
            serialize_tsig(
                &ALGORITHM,
                *TIME_SIGNED,
                FUDGE,
                &[0; 65492],
                ORIGINAL_ID,
                ERROR,
                OTHER,
                &mut buf
            )
            .unwrap_err(),
            RdataTooLongError
        );
    }

    #[test]
    fn new_refuses_to_create_long_rdata() {
        assert_eq!(
            Rdata::new_tsig(
                &ALGORITHM,
                *TIME_SIGNED,
                FUDGE,
                &[0; 65492],
                ORIGINAL_ID,
                ERROR,
                OTHER
            )
            .unwrap_err(),
            RdataTooLongError
        );
    }

    #[test]
    fn validation_works() {
        assert_eq!(
            <&Rdata>::try_from(TSIG_RDATA).unwrap().validate_as_tsig(),
            Ok(()),
        );
    }
}
