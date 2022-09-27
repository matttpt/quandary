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

//! Implementation of Secret Key Authentication for DNS (TSIG), as
//! specified by [RFC 8945].
//!
//! This module implements two basic actions: verification and signing
//! of messages using the TSIG pseudo-RR.
//!
//! For verification, read the TSIG RR from a message using a
//! [`Reader`](super::Reader) and convert the returned [`ReadRr`] into
//! a [`ReadTsigRr`] using [`ReadTsigRr::try_from`]. Then use the
//! [`ReadTsigRr`] `verify_*` methods.
//!
//! For signing, configure a [`PreparedTsigRr`] structure with the
//! appropriate TSIG parameters. Then use its `sign_*` methods to
//! generate the [`Rdata`] to use for the TSIG RR for a message. It's
//! also possible to generate unsigned [`Rdata`] with
//! [`PreparedTsigRr::unsigned`]; this is required for certain error
//! messages, for example. However, in practice, you will generally want
//! to use [`Writer`](super::Writer)'s higher-level API. Just call
//! [`Writer::set_tsig`](super::Writer::set_tsig) with a
//! [`PreparedTsigRr`]. A TSIG RR will then be appended (and if so
//! configured, signed) when you call
//! [`Writer::finish`](super::Writer::finish).
//! ([`Writer`](super::Writer) uses this module's lower-level API under
//! the hood.)
//!
//! Various functionality in this module requires you to specify a TSIG
//! algorithm to use. Supported algorithms are represented by the
//! [`Algorithm`] enumeration. Quandary currently implements the two
//! required TSIG algorithms, HMAC-SHA1 and HMAC-SHA256.
//!
//! [RFC 8945]: https://datatracker.ietf.org/doc/html/rfc8945

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use hmac::digest::{MacError, OutputSizeUser};
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use sha1::Sha1;
use sha2::Sha256;

use crate::name::{LowercaseName, Name};
use crate::rr::rdata::TimeSigned;
use crate::rr::{Rdata, Type};

use super::constants::*;
use super::reader::ReadRr;
use super::{ExtendedRcode, Qclass};

////////////////////////////////////////////////////////////////////////
// TSIG ALGORITHMS                                                    //
////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref HMAC_SHA1_NAME: Box<LowercaseName> = "hmac-sha1.".parse().unwrap();
    static ref HMAC_SHA256_NAME: Box<LowercaseName> = "hmac-sha256.".parse().unwrap();
    static ref ALGORITHMS_BY_NAME: HashMap<&'static Name, Algorithm> = HashMap::from([
        (HMAC_SHA1_NAME.as_ref(), Algorithm::HmacSha1),
        (HMAC_SHA256_NAME.as_ref(), Algorithm::HmacSha256),
    ]);
}

/// A supported TSIG algorithm.
///
/// We currently implement the two algorithms required by
/// [RFC 8945 § 6]: HMAC-SHA1 and HMAC-SHA256.
///
/// [RFC 8945 § 6]: https://datatracker.ietf.org/doc/html/rfc8945#section-6
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    HmacSha1,
    HmacSha256,
}

impl Algorithm {
    /// Returns the name assigned (by [RFC 8945 § 6]) to identify this
    /// algorithm.
    ///
    /// [RFC 8945 § 6]: https://datatracker.ietf.org/doc/html/rfc8945#section-6
    pub fn name(&self) -> &'static LowercaseName {
        match self {
            Self::HmacSha1 => &HMAC_SHA1_NAME,
            Self::HmacSha256 => &HMAC_SHA256_NAME,
        }
    }

    /// Returns the size of the MAC produced by this algorithm.
    pub fn output_size(&self) -> usize {
        match self {
            Self::HmacSha1 => Hmac::<Sha1>::output_size(),
            Self::HmacSha256 => Hmac::<Sha256>::output_size(),
        }
    }

    /// Finds an algorithm by its name (as assigned by [RFC 8945 § 6]).
    /// This returns `None` if the algorithm is not defined or not
    /// supported by this implementation.
    ///
    /// [RFC 8945 § 6]: https://datatracker.ietf.org/doc/html/rfc8945#section-6
    pub fn from_name(name: &Name) -> Option<Self> {
        ALGORITHMS_BY_NAME.get(name).copied()
    }

    /// Creates a MAC authenticator to compute a MAC with this algorithm
    /// and the given key.
    fn make_authenticator(&self, key: &[u8]) -> Box<dyn Authenticator> {
        match self {
            Algorithm::HmacSha1 => Box::new(Hmac::<Sha1>::new_from_slice(key).unwrap()),
            Algorithm::HmacSha256 => Box::new(Hmac::<Sha256>::new_from_slice(key).unwrap()),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TSIG SIGNING AND VERIFICATION HELPERS                              //
////////////////////////////////////////////////////////////////////////

/// An abstraction over different MAC implementations. Basically, this
/// wraps the `digest` crate's [`Mac`] trait to give us an object-safe
/// trait (so that we can use `Box<dyn Authenticator>`).
trait Authenticator {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Box<[u8]>;
    fn verify_truncated_left(self: Box<Self>, tag: &[u8]) -> Result<(), MacError>;
}

impl<M> Authenticator for M
where
    M: Mac,
{
    fn update(&mut self, data: &[u8]) {
        <Self as Mac>::update(self, data);
    }

    fn finalize(self: Box<Self>) -> Box<[u8]> {
        <Self as Mac>::finalize(*self)
            .into_bytes()
            .to_vec()
            .into_boxed_slice()
    }

    fn verify_truncated_left(self: Box<Self>, tag: &[u8]) -> Result<(), MacError> {
        <Self as Mac>::verify_truncated_left(*self, tag)
    }
}

/// An abstraction over data structures that provide the TSIG variables
/// that, per [RFC 8945 § 4.3.3], must be added to the MAC. This allows
/// us to use the same helper functions (below this trait in the source)
/// for verifying and signing.
///
/// [RFC 8945 § 4.3.3]: https://datatracker.ietf.org/doc/html/rfc8945#section-4.3.3
trait Variables {
    fn key_name(&self) -> &LowercaseName;
    fn algorithm(&self) -> &LowercaseName;
    fn time_signed(&self) -> TimeSigned;
    fn fudge(&self) -> u16;
    fn original_id(&self) -> u16;
    fn error(&self) -> ExtendedRcode;
    fn other(&self) -> &[u8];
}

/// Adds the given message to a MAC, decrementing the ARCOUNT and
/// restoring the original message ID first (in accordance with
/// [RFC 8945 § 4.3.2]).
///
/// [RFC 8945 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc8945#section-4.3.2
fn add_modified_message(authenticator: &mut dyn Authenticator, message: &[u8], original_id: u16) {
    authenticator.update(&original_id.to_be_bytes());
    authenticator.update(&message[ID_END..ARCOUNT_START]);
    let arcount_without_tsig =
        u16::from_be_bytes(message[ARCOUNT_START..ARCOUNT_END].try_into().unwrap()) - 1;
    authenticator.update(&arcount_without_tsig.to_be_bytes());
    authenticator.update(&message[ARCOUNT_END..]);
}

/// Adds the TSIG variables specified by [RFC 8945 § 4.3.3] to a MAC.
///
/// [RFC 8945 § 4.3.3]: https://datatracker.ietf.org/doc/html/rfc8945#section-4.3.3
fn add_tsig_variables<V>(authenticator: &mut dyn Authenticator, vars: &V)
where
    V: Variables,
{
    authenticator.update(vars.key_name().wire_repr());
    authenticator.update(b"\x00\xff\x00\x00\x00\x00");
    authenticator.update(vars.algorithm().wire_repr());
    add_tsig_timers(authenticator, vars);
    authenticator.update(&u16::from(vars.error()).to_be_bytes());
    let other = vars.other();
    authenticator.update(&(other.len() as u16).to_be_bytes());
    authenticator.update(other);
}

/// Adds the TSIG timers specified by [RFC 8945 § 4.3.3.1] to a MAC.
///
/// [RFC 8945 § 4.3.3.1]: https://datatracker.ietf.org/doc/html/rfc8945#section-4.3.3.1
fn add_tsig_timers<V>(authenticator: &mut dyn Authenticator, vars: &V)
where
    V: Variables,
{
    authenticator.update(vars.time_signed().as_slice());
    authenticator.update(&vars.fudge().to_be_bytes());
}

////////////////////////////////////////////////////////////////////////
// TSIG READING/VERIFICATION                                          //
////////////////////////////////////////////////////////////////////////

/// A TSIG RR that has been read from a message.
///
/// A [`ReadTsigRr`] is produced by converting a [`ReadRr`] obtained
/// from a [`Reader`](super::Reader) with [`ReadTsigRr::try_from`]. It
/// provides methods to access TSIG fields from the underlying [`Rdata`]
/// and additionally implements TSIG verification through its
/// `validate_*` methods.
#[derive(Clone)]
pub struct ReadTsigRr<'a> {
    key_name: Box<LowercaseName>,
    algorithm: Box<LowercaseName>,
    mac_size: u16,
    rdata: Cow<'a, Rdata>,
}

impl<'a> TryFrom<ReadRr<'a>> for ReadTsigRr<'a> {
    type Error = FromReadRrError;

    fn try_from(rr: ReadRr<'a>) -> Result<Self, Self::Error> {
        if rr.rr_type != Type::TSIG {
            return Err(FromReadRrError::NotTsig);
        } else if rr.class != Qclass::ANY.into() || u32::from(rr.ttl) != 0 {
            return Err(FromReadRrError::FormErr);
        }

        let rdata = rr.rdata.octets();
        let (algorithm, algo_len) = Name::try_from_uncompressed(rdata)
            .expect("failed to read algorithm from already-validated TSIG RDATA");
        let mac_size = u16::from_be_bytes(rdata[algo_len + 8..algo_len + 10].try_into().unwrap());

        Ok(Self {
            key_name: rr.owner.into(),
            algorithm: algorithm.into(),
            mac_size,
            rdata: rr.rdata,
        })
    }
}

impl ReadTsigRr<'_> {
    /// Returns the key name specified by the TSIG RR.
    pub fn key_name(&self) -> &LowercaseName {
        &self.key_name
    }

    /// Returns the algorithm name specified by the TSIG RR.
    pub fn algorithm(&self) -> &LowercaseName {
        &self.algorithm
    }

    /// Returns the time at which the TSIG RR was signed.
    pub fn time_signed(&self) -> TimeSigned {
        let algo_len = self.algorithm.wire_repr().len();
        let array: [u8; 6] = self.rdata.octets()[algo_len..algo_len + 6]
            .try_into()
            .unwrap();
        TimeSigned::from(array)
    }

    /// Returns the fudge field (in seconds) of the TSIG RR.
    pub fn fudge(&self) -> u16 {
        let algo_len = self.algorithm.wire_repr().len();
        u16::from_be_bytes(
            self.rdata.octets()[algo_len + 6..algo_len + 8]
                .try_into()
                .unwrap(),
        )
    }

    /// Returns the MAC of the TSIG RR.
    pub fn mac(&self) -> &[u8] {
        let algo_len = self.algorithm.wire_repr().len();
        let mac_size = self.mac_size as usize;
        &self.rdata.octets()[algo_len + 10..algo_len + mac_size + 10]
    }

    /// Returns the original message ID of the TSIG RR.
    pub fn original_id(&self) -> u16 {
        let algo_len = self.algorithm.wire_repr().len();
        let mac_size = self.mac_size as usize;
        u16::from_be_bytes(
            self.rdata.octets()[algo_len + mac_size + 10..algo_len + mac_size + 12]
                .try_into()
                .unwrap(),
        )
    }

    /// Returns the error field of the TSIG RR.
    pub fn error(&self) -> ExtendedRcode {
        let algo_len = self.algorithm.wire_repr().len();
        let mac_size = self.mac_size as usize;
        ExtendedRcode::from(u16::from_be_bytes(
            self.rdata.octets()[algo_len + mac_size + 12..algo_len + mac_size + 14]
                .try_into()
                .unwrap(),
        ))
    }

    /// Returns the "other data" field of the TSIG RR.
    pub fn other(&self) -> &[u8] {
        // NOTE: since a ReadTsigRr can only be constructed from a
        // ReadRr, whose RDATA has been validated, we know that the
        // length of the slice (taken to the end) will be the same as
        // the length specified in the "other length" field.
        let algo_len = self.algorithm.wire_repr().len();
        let mac_size = self.mac_size as usize;
        &self.rdata.octets()[algo_len + mac_size + 16..]
    }

    /// Verifies the given request message.
    ///
    /// The passed buffer should be the message up to—but not
    /// including—the TSIG RR. It must be a valid DNS message.
    /// Furthermore, the algorithm provided must match the algorithm
    /// name in the RR. Failure to uphold these preconditions may result
    /// in a panic.
    ///
    /// However, it is not required to decrement the message ARCOUNT or
    /// to reset its message ID to the original ID in the TSIG RR. This
    /// method does this for you.
    pub fn verify_request(
        &self,
        message: &[u8],
        algorithm: Algorithm,
        key: &[u8],
        now: TimeSigned,
    ) -> Result<(), VerificationError> {
        let add_data_to_mac = |authenticator: &mut dyn Authenticator| {
            add_modified_message(authenticator, message, self.original_id());
            add_tsig_variables(authenticator, self);
        };
        self.verification_core(add_data_to_mac, algorithm, key, now)
    }

    /// Verifies the given response message.
    ///
    /// The passed buffer should be the message up to—but not
    /// including—the TSIG RR. It must be a valid DNS message.
    /// Furthermore, the algorithm provided must match the algorithm
    /// name in the RR. Finally, the request MAC must fit in the TSIG
    /// MAC field (i.e., it must be no more than 65,535 octets long).
    /// Failure to uphold these preconditions may result in a panic.
    ///
    /// However, it is not required to decrement the message ARCOUNT or
    /// to reset its message ID to the original ID in the TSIG RR. This
    /// method does this for you.
    pub fn verify_response(
        &self,
        message: &[u8],
        request_mac: &[u8],
        algorithm: Algorithm,
        key: &[u8],
        now: TimeSigned,
    ) -> Result<(), VerificationError> {
        assert!(request_mac.len() <= u16::MAX as usize);
        let add_data_to_mac = |authenticator: &mut dyn Authenticator| {
            authenticator.update(&(request_mac.len() as u16).to_be_bytes());
            authenticator.update(request_mac);
            add_modified_message(authenticator, message, self.original_id());
            add_tsig_variables(authenticator, self);
        };
        self.verification_core(add_data_to_mac, algorithm, key, now)
    }

    /// The internal core implementation of TSIG message verification.
    fn verification_core<F>(
        &self,
        add_data_to_mac: F,
        algorithm: Algorithm,
        key: &[u8],
        now: TimeSigned,
    ) -> Result<(), VerificationError>
    where
        F: FnOnce(&mut dyn Authenticator),
    {
        // Ensure that the algorithm the caller provided is actually
        // the algorithm used to sign.
        assert_eq!(self.algorithm(), algorithm.name());

        // Ensure that any MAC truncation applied is in meets RFC 8945
        // § 5.2.2.1's minimum requirements.
        check_mac_size(algorithm, self.mac_size)?;

        // RFC 8945 § 5.2.2: verify the MAC.
        let mut authenticator = algorithm.make_authenticator(key);
        add_data_to_mac(authenticator.as_mut());
        authenticator
            .verify_truncated_left(self.mac())
            .or(Err(VerificationError::BadSig))?;

        // RFC 8945 § 5.2.3: ensure that the time signed is close enough
        // to the server time.
        check_time(self.time_signed(), self.fudge(), now)?;

        // RFC 8495 § 5.2.4: ensure that the MAC is long enough to meet
        // local policy requirements. Right now, we have a hard-coded
        // local policy: accept anything that meets the minimum
        // requirements of RFC 8945 § 5.2.2.1. Specification of local
        // policy is a TODO item.

        Ok(())
    }
}

/// Ensures that the MAC size is acceptable, per [RFC 8945 § 5.2.2.1].
///
/// [RFC 8945 § 5.2.2.1]: https://datatracker.ietf.org/doc/html/rfc8945#section-5.2.2.1
fn check_mac_size(algorithm: Algorithm, mac_size: u16) -> Result<(), VerificationError> {
    let mac_size = mac_size as usize;
    let half_output_size = (algorithm.output_size() + 1) / 2;
    if mac_size > algorithm.output_size() || mac_size < 10.max(half_output_size) {
        Err(VerificationError::FormErr)
    } else {
        Ok(())
    }
}

/// Checks that `time_signed` does not deviate more than `fudge` seconds
/// from the "current" time (specified by `now`).
fn check_time(
    time_signed: TimeSigned,
    fudge: u16,
    now: TimeSigned,
) -> Result<(), VerificationError> {
    let time_signed_unix = time_signed.to_unix_time();
    let now_unix = now.to_unix_time();
    let time_window_start = time_signed_unix.saturating_sub(fudge as u64);
    let time_window_end = time_signed_unix.saturating_add(fudge as u64);

    if now_unix >= time_window_start && now_unix <= time_window_end {
        Ok(())
    } else {
        Err(VerificationError::BadTime)
    }
}

impl Variables for ReadTsigRr<'_> {
    fn key_name(&self) -> &LowercaseName {
        self.key_name()
    }

    fn algorithm(&self) -> &LowercaseName {
        self.algorithm()
    }

    fn time_signed(&self) -> TimeSigned {
        self.time_signed()
    }

    fn fudge(&self) -> u16 {
        self.fudge()
    }

    fn original_id(&self) -> u16 {
        self.original_id()
    }

    fn error(&self) -> ExtendedRcode {
        self.error()
    }

    fn other(&self) -> &[u8] {
        self.other()
    }
}

impl fmt::Debug for ReadTsigRr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ReadTsigRr")
            .field("key_name", &self.key_name())
            .field("algorithm", &self.algorithm())
            .field("time_signed", &self.time_signed())
            .field("fudge", &self.fudge())
            .field("mac", &self.mac())
            .field("original_id", &self.original_id())
            .field("error", &self.error())
            .field("other", &self.other())
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////
// TSIG WRITING/SIGNING                                               //
////////////////////////////////////////////////////////////////////////

/// A TSIG RR that has been prepared for serialization.
///
/// This structure specifies TSIG fields other than the signing
/// algorithm and MAC. The fields can be prepared manually, or filled in
/// (for a response) from the [`ReadTsigRr`] of a request with
/// [`PreparedTsigRr::new_from_read`]. (Note that the
/// [`PreparedTsigRr::server_time`] is ignored unless the error is
/// [`ExtendedRcode::BADTIME`].)
///
/// When a message is complete, a [`PreparedTsigRr`] can be used to sign
/// it through its `sign_*` methods. Given the required digest
/// components, an algorithm, and a key, these compute the MAC and then
/// serialize TSIG [`Rdata`] from the structure's fields and the MAC.
/// For unsigned TSIG records, [`PreparedTsigRr::unsigned`] produces
/// [`Rdata`] from the structure's fields and an empty MAC.
#[derive(Debug, Clone)]
pub struct PreparedTsigRr {
    pub key_name: Box<LowercaseName>,
    pub time_signed: TimeSigned,
    pub fudge: u16,
    pub original_id: u16,
    pub error: ExtendedRcode,
    pub server_time: TimeSigned,
}

impl PreparedTsigRr {
    /// Creates a `PreparedTsigRr` for a response by combining fields
    /// from a [`ReadTsigRr`] from the request and the provided
    /// arguments.
    ///
    /// If the error is [`ExtendedRcode::BADTIME`], then per
    /// [RFC 8945 § 5.4.3], the time signed field is taken from the
    /// request and the `time_signed` argument is placed in the
    /// `server_time` field. Otherwise, the `time_signed` field is
    /// placed into both fields (and the `server_time` field is not used
    /// when the TSIG RDATA is serialized).
    ///
    /// [RFC 8945 § 5.4.3]: https://datatracker.ietf.org/doc/html/rfc8945#section-5.2.3
    pub fn new_from_read(
        read: &ReadTsigRr,
        time_signed: TimeSigned,
        fudge: u16,
        error: ExtendedRcode,
    ) -> Self {
        let (time_signed, server_time) = if error == ExtendedRcode::BADTIME {
            (read.time_signed(), time_signed)
        } else {
            (time_signed, time_signed)
        };
        Self {
            key_name: read.key_name.clone(),
            time_signed,
            fudge,
            original_id: read.original_id(),
            error,
            server_time,
        }
    }

    /// Returns the maximum length of the TSIG RR (i.e., assuming that
    /// the owner name is not compressed) if it contains the provided
    /// algorithm name and is left unsigned.
    pub fn unsigned_len(&self, algorithm: &Name) -> usize {
        let mut len = self.key_name.wire_repr().len() + algorithm.wire_repr().len() + 26;
        if self.error == ExtendedRcode::BADTIME {
            len += 6;
        }
        len
    }

    /// Returns the maximum length of the TSIG RR (i.e., assuming that
    /// the owner name is not compressed) if it is signed with the given
    /// algorithm.
    pub fn signed_len(&self, algorithm: Algorithm) -> usize {
        self.unsigned_len(algorithm.name()) + algorithm.output_size()
    }

    /// Signs the given request message, returning TSIG [`Rdata`] with
    /// the computed MAC.
    ///
    /// The passed buffer should be the message up to—but not
    /// including—the TSIG RR. It must be a valid DNS message (once the
    /// TSIG RR is appended). Failure to uphold these preconditions may
    /// result in a panic.
    ///
    /// Note that the message's ID and ARCOUNT should be set to their
    /// final values (i.e. for the latter, including the TSIG RR); this
    /// method takes care of adjusting these fields as appropriate when
    /// computing the MAC.
    pub fn sign_request(
        &self,
        message: &[u8],
        algorithm: Algorithm,
        key: &[u8],
    ) -> (Box<Rdata>, Box<[u8]>) {
        let mut authenticator = algorithm.make_authenticator(key);
        add_modified_message(authenticator.as_mut(), message, self.original_id);
        add_tsig_variables(authenticator.as_mut(), &(algorithm.name(), self));
        let mac = authenticator.finalize();
        (self.serialize_rdata(algorithm.name(), &mac), mac)
    }

    /// Signs the given response message, returning TSIG [`Rdata`] with
    /// the computed MAC.
    ///
    /// The passed buffer should be the message up to—but not
    /// including—the TSIG RR. It must be a valid DNS message (once the
    /// TSIG RR is appended). Furthermore, the request MAC must be a
    /// valid TSIG MAC (i.e., it must be no more than 65,535 octets
    /// long). Failure to uphold these preconditions may result in a
    /// panic.
    ///
    /// Note that the message's ID and ARCOUNT should be set to their
    /// final values (i.e. for the latter, including the TSIG RR); this
    /// method takes care of adjusting these fields as appropriate when
    /// computing the MAC.
    pub fn sign_response(
        &self,
        message: &[u8],
        request_mac: &[u8],
        algorithm: Algorithm,
        key: &[u8],
    ) -> (Box<Rdata>, Box<[u8]>) {
        assert!(request_mac.len() <= u16::MAX as usize);
        let mut authenticator = algorithm.make_authenticator(key);
        authenticator.update(&(request_mac.len() as u16).to_be_bytes());
        authenticator.update(request_mac);
        add_modified_message(authenticator.as_mut(), message, self.original_id);
        add_tsig_variables(authenticator.as_mut(), &(algorithm.name(), self));
        let mac = authenticator.finalize();
        (self.serialize_rdata(algorithm.name(), &mac), mac)
    }

    /// Serializes TSIG [`Rdata`] using the provided algorithm name and
    /// leaving the record unsigned (i.e., with a zero-length MAC).
    pub fn unsigned(&self, algorithm: &LowercaseName) -> Box<Rdata> {
        self.serialize_rdata(algorithm, &[])
    }

    /// An internal helper to serialize TSIG [`Rdata`].
    fn serialize_rdata(&self, algorithm: &LowercaseName, mac: &[u8]) -> Box<Rdata> {
        Rdata::new_tsig(
            algorithm,
            self.time_signed,
            self.fudge,
            mac,
            self.original_id,
            self.error,
            self.other(),
        )
        .expect("serialized TSIG RDATA was too long; this is a bug")
    }

    /// Returns the "other data" field to serialize.
    fn other(&self) -> &[u8] {
        if self.error == ExtendedRcode::BADTIME {
            self.server_time.as_slice()
        } else {
            &[]
        }
    }
}

impl Variables for (&LowercaseName, &PreparedTsigRr) {
    fn key_name(&self) -> &LowercaseName {
        &self.1.key_name
    }

    fn algorithm(&self) -> &LowercaseName {
        self.0
    }

    fn time_signed(&self) -> TimeSigned {
        self.1.time_signed
    }

    fn fudge(&self) -> u16 {
        self.1.fudge
    }

    fn original_id(&self) -> u16 {
        self.1.original_id
    }

    fn error(&self) -> ExtendedRcode {
        self.1.error
    }

    fn other(&self) -> &[u8] {
        self.1.other()
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// Errors that arise when a [`ReadRr`] cannot be converted into a
/// [`ReadTsigRr`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum FromReadRrError {
    /// There is a format error in the RDATA.
    FormErr,

    /// The [`ReadRr`] is not a TSIG record.
    NotTsig,
}

impl fmt::Display for FromReadRrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FormErr => f.write_str("FORMERR"),
            Self::NotTsig => f.write_str("RR type is not TSIG"),
        }
    }
}

/// Errors that arise during TSIG verification.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum VerificationError {
    /// MAC verification failed. A response to this message must not be
    /// signed.
    BadSig,

    /// Time check failed. A response to this message must be signed.
    BadTime,

    /// There was a format error (due to the MAC not meeting the minimum
    /// requirements of [RFC 8945 § 5.2.2.1]). A response to this
    /// message must not be signed.
    ///
    /// [RFC 8945 § 5.2.2.1]: https://datatracker.ietf.org/doc/html/rfc8945#section-5.2.2.1
    FormErr,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadSig => f.write_str("BADSIG"),
            Self::BadTime => f.write_str("BADTIME"),
            Self::FormErr => f.write_str("FORMERR"),
        }
    }
}

impl std::error::Error for VerificationError {}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use crate::class::Class;
    use crate::name::LowercaseName;
    use crate::rr::rdata::TimeSigned;
    use crate::rr::{Ttl, Type};

    use super::super::writer::{Hint, HintedName, TsigMode};
    use super::super::{ExtendedRcode, Question, Reader, Writer};
    use super::{Algorithm, PreparedTsigRr, ReadTsigRr, VerificationError};

    const REQUEST_WITH_TSIG: &[u8] =
        b"\xa2\xe0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x08\x71\x75\x61\
          \x6e\x64\x61\x72\x79\x04\x74\x65\x73\x74\x00\x00\x10\x00\x01\x01\
          \x61\x04\x74\x73\x69\x67\x03\x6b\x65\x79\x00\x00\xfa\x00\xff\x00\
          \x00\x00\x00\x00\x3d\x0b\x68\x6d\x61\x63\x2d\x73\x68\x61\x32\x35\
          \x36\x00\x00\x00\x63\x2b\x8d\xca\x01\x2c\x00\x20\xbb\x33\x6e\x57\
          \x42\xa7\xa6\xce\x41\x37\x1b\x96\x84\x8b\x3b\x21\x26\x95\x94\x37\
          \x15\xc2\xaa\xd9\x37\x9d\xd9\xaa\xaa\x75\x39\xb8\xa2\xe0\x00\x00\
          \x00\x00";
    const RESPONSE_WITH_TSIG: &[u8] =
        b"\xa2\xe0\x84\x00\x00\x01\x00\x01\x00\x00\x00\x01\x08\x71\x75\x61\
          \x6e\x64\x61\x72\x79\x04\x74\x65\x73\x74\x00\x00\x10\x00\x01\xc0\
          \x0c\x00\x10\x00\x01\x00\x01\x51\x80\x00\x0a\x09\x49\x74\x20\x77\
          \x6f\x72\x6b\x73\x21\x01\x61\x04\x74\x73\x69\x67\x03\x6b\x65\x79\
          \x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3d\x0b\x68\x6d\x61\x63\
          \x2d\x73\x68\x61\x32\x35\x36\x00\x00\x00\x63\x2b\x8d\xca\x01\x2c\
          \x00\x20\xb9\x7f\x50\x3b\xd0\x93\x4d\xcf\x84\xf5\xf4\x89\xb5\xed\
          \xde\x52\x7d\x28\x28\x32\xd5\xe1\xd8\x3c\x0a\xb2\x43\xb6\x43\x9f\
          \xc2\x56\xa2\xe0\x00\x00\x00\x00";

    const MESSAGE_ID: u16 = 0xa2e0;
    const FUDGE: u16 = 300;
    const KEY: &[u8] = b"topsecret";

    lazy_static! {
        static ref CORRUPTED_REQUEST_WITH_TSIG: Box<[u8]> = {
            let mut corrupted: Box<[u8]> = REQUEST_WITH_TSIG.into();
            corrupted[2] = 0xff;
            corrupted
        };
        static ref CORRUPTED_RESPONSE_WITH_TSIG: Box<[u8]> = {
            let mut corrupted: Box<[u8]> = RESPONSE_WITH_TSIG.into();
            corrupted[2] = 0xff;
            corrupted
        };
        static ref KEY_NAME: Box<LowercaseName> = "a.tsig.key.".parse().unwrap();
        static ref TIME_SIGNED: TimeSigned = TimeSigned::try_from_unix_time(1663798730).unwrap();
        static ref TOO_EARLY: TimeSigned =
            TimeSigned::try_from_unix_time(1663798730 - FUDGE as u64 - 1).unwrap();
        static ref TOO_LATE: TimeSigned =
            TimeSigned::try_from_unix_time(1663798730 + FUDGE as u64 + 1).unwrap();
        static ref REQUEST_MAC: &'static [u8] = &REQUEST_WITH_TSIG[76..108];
        static ref QUESTION: Question = Question {
            qname: "quandary.test.".parse().unwrap(),
            qtype: Type::TXT.into(),
            qclass: Class::IN.into(),
        };
    }

    fn read_message(
        message: &'static [u8],
        rrs_to_skip: usize,
    ) -> (&'static [u8], ReadTsigRr<'static>) {
        let mut reader = Reader::try_from(message).unwrap();
        reader.read_question().unwrap();
        for _ in 0..rrs_to_skip {
            reader.skip_rr().unwrap();
        }
        let message_up_to_tsig = reader.message_to_cursor();
        let tsig_rr = ReadTsigRr::try_from(reader.read_rr().unwrap()).unwrap();
        (message_up_to_tsig, tsig_rr)
    }

    fn read_request() -> (&'static [u8], ReadTsigRr<'static>) {
        read_message(REQUEST_WITH_TSIG, 0)
    }

    fn read_corrupted_request() -> (&'static [u8], ReadTsigRr<'static>) {
        read_message(&CORRUPTED_REQUEST_WITH_TSIG, 0)
    }

    fn read_response() -> (&'static [u8], ReadTsigRr<'static>) {
        read_message(RESPONSE_WITH_TSIG, 1)
    }

    fn read_corrupted_response() -> (&'static [u8], ReadTsigRr<'static>) {
        read_message(&CORRUPTED_RESPONSE_WITH_TSIG, 1)
    }

    ////////////////////////////////////////////////////////////////////
    // TSIG READING/VERIFICATION TESTS                                //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn read_tsig_rr_accessors_work() {
        let (_, tsig_rr) = read_request();
        assert_eq!(tsig_rr.algorithm(), Algorithm::HmacSha256.name());
        assert_eq!(tsig_rr.time_signed(), *TIME_SIGNED);
        assert_eq!(tsig_rr.fudge(), FUDGE);
        assert_eq!(tsig_rr.mac(), *REQUEST_MAC);
        assert_eq!(tsig_rr.original_id(), MESSAGE_ID);
        assert_eq!(tsig_rr.error(), ExtendedRcode::NOERROR);
        assert_eq!(tsig_rr.other(), &[]);
    }

    fn request_verification_helper(
        now: TimeSigned,
        corrupted: bool,
        expected: Result<(), VerificationError>,
    ) {
        let (message_up_to_tsig, tsig_rr) = if corrupted {
            read_corrupted_request()
        } else {
            read_request()
        };
        assert_eq!(
            tsig_rr.verify_request(message_up_to_tsig, Algorithm::HmacSha256, KEY, now),
            expected,
        );
    }

    #[test]
    fn request_verification_works() {
        request_verification_helper(*TIME_SIGNED, false, Ok(()));
    }

    #[test]
    fn request_verification_rejects_corrupted_message() {
        request_verification_helper(*TIME_SIGNED, true, Err(VerificationError::BadSig));
    }

    #[test]
    fn request_verification_rejects_late_message() {
        request_verification_helper(*TOO_LATE, false, Err(VerificationError::BadTime));
    }

    #[test]
    fn request_verification_rejects_early_message() {
        request_verification_helper(*TOO_EARLY, false, Err(VerificationError::BadTime));
    }

    fn response_verification_helper(
        now: TimeSigned,
        corrupted: bool,
        expected: Result<(), VerificationError>,
    ) {
        let (message_up_to_tsig, tsig_rr) = if corrupted {
            read_corrupted_response()
        } else {
            read_response()
        };
        assert_eq!(
            tsig_rr.verify_response(
                message_up_to_tsig,
                *REQUEST_MAC,
                Algorithm::HmacSha256,
                KEY,
                now
            ),
            expected,
        );
    }

    #[test]
    fn response_verification_works() {
        response_verification_helper(*TIME_SIGNED, false, Ok(()));
    }

    #[test]
    fn response_verification_rejects_corrupted_message() {
        response_verification_helper(*TIME_SIGNED, true, Err(VerificationError::BadSig));
    }

    #[test]
    fn response_verification_rejects_late_message() {
        response_verification_helper(*TOO_LATE, false, Err(VerificationError::BadTime));
    }

    #[test]
    fn response_verification_rejects_early_message() {
        response_verification_helper(*TOO_EARLY, false, Err(VerificationError::BadTime));
    }

    ////////////////////////////////////////////////////////////////////
    // TSIG WRITING/SIGNING TESTS                                     //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn request_signing_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_id(MESSAGE_ID);
        writer.add_question(&QUESTION).unwrap();
        let tsig_rr = PreparedTsigRr {
            key_name: KEY_NAME.clone(),
            time_signed: *TIME_SIGNED,
            fudge: FUDGE,
            original_id: MESSAGE_ID,
            error: ExtendedRcode::NOERROR,
            server_time: *TIME_SIGNED,
        };
        let tsig_mode = TsigMode::Request {
            algorithm: Algorithm::HmacSha256,
            key: KEY.into(),
        };
        writer.set_tsig(tsig_mode, tsig_rr).unwrap();
        let len = writer.finish();
        assert_eq!(REQUEST_WITH_TSIG, &buf[0..len]);
    }

    #[test]
    fn response_signing_works() {
        let (_, request_tsig) = read_request();
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_id(MESSAGE_ID);
        writer.set_qr(true);
        writer.set_aa(true);
        writer.add_question(&QUESTION).unwrap();
        writer
            .add_answer_rr(
                HintedName::new(Hint::Qname, &QUESTION.qname),
                QUESTION.qtype.into(),
                QUESTION.qclass.into(),
                Ttl::from(86400),
                b"\x09It works!".try_into().unwrap(),
            )
            .unwrap();
        let tsig_mode = TsigMode::Response {
            request_mac: (*REQUEST_MAC).into(),
            algorithm: Algorithm::HmacSha256,
            key: KEY.into(),
        };
        let tsig_rr = PreparedTsigRr::new_from_read(
            &request_tsig,
            *TIME_SIGNED,
            FUDGE,
            ExtendedRcode::NOERROR,
        );
        writer.set_tsig(tsig_mode, tsig_rr).unwrap();
        let len = writer.finish();
        assert_eq!(RESPONSE_WITH_TSIG, &buf[0..len]);
    }
}
