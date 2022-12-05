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

//! Implementation of the [`Writer`] type to write on-the-wire DNS
//! messages.

use std::fmt;
use std::num::NonZeroU16;

use arrayvec::ArrayVec;

use super::constants::*;
use super::tsig::{Algorithm, PreparedTsigRr};
use super::{ExtendedRcode, Opcode, Qclass, Question, Rcode};
use crate::class::Class;
use crate::name::{LowercaseName, Name};
use crate::rr::rdata::{Component, TimeSigned};
use crate::rr::{Rdata, RdataSet, Ttl, Type};

////////////////////////////////////////////////////////////////////////
// WRITER                                                             //
////////////////////////////////////////////////////////////////////////

/// A "frame" around a buffer that serializes a DNS message into it.
///
/// A `Writer` is constructed using [`Writer::new`] (to set an initial
/// message size limit different from the underlying buffer size) or
/// with its [`TryFrom`] implementation (which sets the message size
/// limit equal to the buffer length). The underlying buffer and initial
/// message size limit must be long enough to accommodate a full DNS
/// message header of 12 octets. The message header is initially zeroed.
///
/// Since header information is in a fixed position, it can be written
/// at any time through the appropriate `Writer` methods. For
/// serializing questions and resource records, the following methods
/// are available:
///
/// * [`Writer::add_question`];
/// * [`Writer::add_answer_rr`] and [`Writer::add_answer_rrset`];
/// * [`Writer::add_authority_rr`] and [`Writer::add_authority_rrset`];
///   and
/// * [`Writer::add_additional_rr`] and
///   [`Writer::add_additional_rrset`].
///
/// Questions and resource records are written sequentially into the
/// buffer based on a cursor. Thus the above methods must be used in the
/// proper order (questions, answer RRs, authority RRs, additional RRs).
/// To ensure this, the [`Writer`] keeps track of the section of the DNS
/// message body it is currently writing. Attempts to use the above
/// methods out of order will fail with [`Error::OutOfOrder`].
///
/// For EDNS messages, use [`Writer::set_edns`]. Space for an OPT record
/// will be reserved, and the OPT record will be automatically added to
/// the message when [`Writer::finish`] is called.
///
/// For messages with TSIG authentication, use [`Writer::set_tsig`].
/// Space for a TSIG record will be reserved, and the TSIG record will
/// be automatically added as the last RR when [`Writer::finish`] is
/// called.
pub struct Writer<'a> {
    octets: &'a mut [u8],
    cursor: usize,
    limit: usize,
    available: usize,
    rr_start: usize,
    section: Section,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    qname: Option<PriorName>,
    most_recent_owner: Option<PriorName>,
    most_recent_name_in_rdata: Option<PriorName>,
    compression_mode: CompressionMode,
    edns: Option<Edns>,
    tsig: Option<Tsig>,
}

/// A reusable template for a DNS message.
///
/// A `Template` stores the state of a [`Writer`], including a copy of
/// the message that it has written so far. It can then be used to
/// construct new [`Writer`]s that start out with the same state. This
/// is useful for serializing many similar messages, for example as part
/// of a multi-message AXFR response.
///
/// To generate a `Template` from a [`Writer`], use
/// [`Writer::into_template`]. To start a new [`Writer`] from a
/// `Template`, use [`Writer::try_from_template`] or one of its
/// variants.
#[derive(Clone)]
pub struct Template {
    octets: Box<[u8]>,
    limit: usize,
    reserved: usize,
    rr_start: usize,
    section: Section,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    qname: Option<PriorName>,
    most_recent_owner: Option<PriorName>,
    most_recent_name_in_rdata: Option<PriorName>,
    compression_mode: CompressionMode,
    edns: Option<Edns>,
    tsig: Option<Tsig>,
}

/// A type for recording which section of a DNS message a [`Writer`] is
/// currently serializing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Section {
    Question,
    Answer,
    Authority,
    Additional,
}

/// Records where a name was written in a message and how many labels
/// long it is.
#[derive(Clone, Copy, Debug)]
struct PriorName {
    pointer: HintPointer,
    len: u8,
}

impl PriorName {
    /// Creates a new `PriorName`.
    fn new(pointer: HintPointer, name: &Name) -> Self {
        Self {
            pointer,
            len: name.len() as u8,
        }
    }
}

/// How a [`Writer`] may (when allowed by the DNS standard) compress
/// domain names in a message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CompressionMode {
    /// Perform standard compression. Case is not preserved.
    Standard,

    /// Perform case-preserving compression. This is recommended for
    /// AXFR; see [RFC 5936 § 3.4].
    ///
    /// [RFC 5936 § 3.4]: https://datatracker.ietf.org/doc/html/rfc5936#section-3.4
    CasePreserving,

    /// Do not compress domain names. However, note that
    /// [RFC 1123 § 6.1.2.4] requires name servers to use compression
    /// in responses, since it helps prevent truncation and retries over
    /// TCP. (Even with EDNS, the point still stands.)
    ///
    /// [RFC 1123 § 6.1.2.4]: https://datatracker.ietf.org/doc/html/rfc1123#section-6.1.2.4
    Disabled,
}

/// A type for recording EDNS information for a message until it is
/// serialized in [`Writer::finish`].
#[derive(Clone, Debug)]
struct Edns {
    udp_payload_size: u16,
    extended_rcode_upper_bits: u8,
}

/// A type for recording TSIG information for a message until it is
/// serialized in [`Writer::finish`].
#[derive(Clone, Debug)]
struct Tsig {
    mode: TsigMode,
    reserved_len: usize,
    rr: PreparedTsigRr,
}

/// Specifies if and how to sign a message with a TSIG RR.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TsigMode {
    /// The message should be signed as a request.
    Request {
        algorithm: Algorithm,
        key: Box<[u8]>,
    },

    /// The message should be signed as a response.
    Response {
        algorithm: Algorithm,
        request_mac: Box<[u8]>,
        key: Box<[u8]>,
    },

    /// The message should be signed as a subsequent message in a
    /// multi-message response.
    Subsequent {
        algorithm: Algorithm,
        prior_mac: Box<[u8]>,
        key: Box<[u8]>,
    },

    /// The message should not be signed. The MAC field of the TSIG RR
    /// will be left empty.
    Unsigned { algorithm: Box<LowercaseName> },
}

/// The amount of space we need to reserve for the OPT record. (Since we
/// don't use any EDNS options right now, the OPT record is a fixed
/// size.)
const OPT_RECORD_SIZE: usize = 11;

impl<'a> Writer<'a> {
    /// Creates a new `Writer` from the underlying buffer `octets`. The
    /// message size is initially limited to `limit` or `octets.len()`
    /// (whichever is smaller). If the smaller limit is too small to
    /// hold a full DNS message header of 12 octets, then this will
    /// fail.
    pub fn new(octets: &'a mut [u8], limit: usize) -> Result<Self> {
        let limit = limit.min(octets.len());
        if limit < HEADER_SIZE {
            Err(Error::Truncation)
        } else {
            octets[0..HEADER_SIZE].fill(0);
            Ok(Self {
                octets,
                cursor: HEADER_SIZE,
                limit,
                available: limit,
                rr_start: HEADER_SIZE,
                section: Section::Question,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
                qname: None,
                most_recent_owner: None,
                most_recent_name_in_rdata: None,
                compression_mode: CompressionMode::Standard,
                edns: None,
                tsig: None,
            })
        }
    }

    /// Converts this `Writer` into a [`Template`], consuming `self`.
    pub fn into_template(self) -> Template {
        let octets = self.octets[0..self.cursor].into();
        Template {
            octets,
            limit: self.limit,
            reserved: self.limit - self.available,
            rr_start: self.rr_start,
            section: self.section,
            qdcount: self.qdcount,
            ancount: self.ancount,
            nscount: self.nscount,
            arcount: self.arcount,
            qname: self.qname,
            most_recent_owner: self.most_recent_owner,
            most_recent_name_in_rdata: self.most_recent_name_in_rdata,
            compression_mode: self.compression_mode,
            edns: self.edns,
            tsig: self.tsig,
        }
    }

    /// Creates a new `Writer` from a [`Template`].
    ///
    /// This will fail if the provided buffer is not large enough to
    /// accommodate both the in-progress message stored in the
    /// [`Template`] and any reserved space (e.g. for OPT or TSIG
    /// records). If the buffer meets this requirement but is smaller
    /// than the [`Template`]'s stored message size limit, then the
    /// limit will be reduced to the buffer size.
    pub fn try_from_template(octets: &'a mut [u8], template: &Template) -> Result<Self> {
        Self::try_from_template_impl(octets, template, template.tsig.clone())
    }

    /// Like [`Writer::try_from_template`], but overrides the TSIG mode,
    /// setting it to [`TsigMode::Subsequent`]. The MAC of the prior
    /// signed message must be provided. In addition to the requirements
    /// of [`Writer::try_from_template`], this will fail if the
    /// [`TsigMode`] of the [`Template`] is not one of the signing
    /// modes.
    pub fn try_from_template_as_tsig_subsequent(
        octets: &'a mut [u8],
        template: &Template,
        prior_mac: Box<[u8]>,
    ) -> Result<Self> {
        if let Some(tsig) = &template.tsig {
            let (algorithm, key) = match &tsig.mode {
                TsigMode::Request { algorithm, key, .. }
                | TsigMode::Response { algorithm, key, .. }
                | TsigMode::Subsequent { algorithm, key, .. } => (*algorithm, key.clone()),
                _ => return Err(Error::NotSignedTsig),
            };
            let new_tsig = Tsig {
                mode: TsigMode::Subsequent {
                    algorithm,
                    key,
                    prior_mac,
                },
                reserved_len: tsig.reserved_len,
                rr: tsig.rr.clone(),
            };
            Self::try_from_template_impl(octets, template, Some(new_tsig))
        } else {
            Err(Error::NotTsig)
        }
    }

    /// The underlying implementation for [`Writer::try_from_template`]
    /// and [`Writer::try_from_template_as_tsig_subsequent`].
    fn try_from_template_impl(
        octets: &'a mut [u8],
        template: &Template,
        tsig: Option<Tsig>,
    ) -> Result<Self> {
        let cursor = template.octets.len();
        if octets.len() < cursor + template.reserved {
            Err(Error::Truncation)
        } else {
            let limit = template.limit.min(octets.len());
            let available = limit - template.reserved;
            octets[0..cursor].copy_from_slice(template.octets.as_ref());
            Ok(Self {
                octets,
                cursor,
                limit,
                available,
                rr_start: template.rr_start,
                section: template.section,
                qdcount: template.qdcount,
                ancount: template.ancount,
                nscount: template.nscount,
                arcount: template.arcount,
                qname: template.qname,
                most_recent_owner: template.most_recent_owner,
                most_recent_name_in_rdata: template.most_recent_name_in_rdata,
                compression_mode: template.compression_mode,
                edns: template.edns.clone(),
                tsig,
            })
        }
    }

    /// Sets the size limit for the message as close to `new_limit` as
    /// possible. Note that this method silently clamps the value: the
    /// limit cannot be more than the underlying buffer's size and
    /// cannot be less than the length of the message written so far,
    /// plus any reserved space.
    pub fn set_limit(&mut self, new_limit: usize) {
        if new_limit >= self.limit {
            let new_limit = new_limit.min(self.octets.len());
            let increase = new_limit - self.limit;
            self.limit = new_limit;
            self.available += increase;
        } else {
            let new_limit = new_limit.max(self.cursor + self.limit - self.available);
            let decrease = self.limit - new_limit;
            self.limit = new_limit;
            self.available -= decrease;
        }
    }

    /// Configures how the `Writer` may (when allowed by the DNS
    /// standard) compress domain names in the message.
    ///
    /// Compression is enabled and case-insensitive by default. Changing
    /// this setting does not affect domain names already written.
    pub fn set_compression_mode(&mut self, mode: CompressionMode) {
        self.compression_mode = mode;
    }

    /// Returns the current 16-bit ID of the message.
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.octets[ID_START..ID_END].try_into().unwrap())
    }

    /// Sets the 16-bit ID of the message.
    pub fn set_id(&mut self, id: u16) {
        self.write_u16(ID_START, id);
    }

    /// Returns the current value of the QR (query response) bit.
    pub fn qr(&self) -> bool {
        (self.octets[QR_BYTE] & QR_MASK) != 0
    }

    /// Sets or clears the QR (query response) bit.
    pub fn set_qr(&mut self, qr: bool) {
        if qr {
            self.octets[QR_BYTE] |= QR_MASK;
        } else {
            self.octets[QR_BYTE] &= !QR_MASK;
        }
    }

    /// Returns the message's current opcode.
    pub fn opcode(&self) -> Opcode {
        let raw = (self.octets[OPCODE_BYTE] & OPCODE_MASK) >> OPCODE_SHIFT;
        raw.try_into().unwrap()
    }

    /// Sets the message's opcode.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.octets[OPCODE_BYTE] &= !OPCODE_MASK;
        self.octets[OPCODE_BYTE] |= u8::from(opcode) << OPCODE_SHIFT;
    }

    /// Returns the current value of the AA (authoritative answer) bit.
    pub fn aa(&self) -> bool {
        (self.octets[AA_BYTE] & AA_MASK) != 0
    }

    /// Sets or clears the AA (authoritative answer) bit.
    pub fn set_aa(&mut self, aa: bool) {
        if aa {
            self.octets[AA_BYTE] |= AA_MASK;
        } else {
            self.octets[AA_BYTE] &= !AA_MASK;
        }
    }

    /// Returns the current value of the TC (truncation) bit.
    pub fn tc(&self) -> bool {
        (self.octets[TC_BYTE] & TC_MASK) != 0
    }

    /// Sets or clears the TC (truncation) bit.
    pub fn set_tc(&mut self, tc: bool) {
        if tc {
            self.octets[TC_BYTE] |= TC_MASK;
        } else {
            self.octets[TC_BYTE] &= !TC_MASK;
        }
    }

    /// Returns the current value of the RD (recursion desired) bit.
    pub fn rd(&self) -> bool {
        (self.octets[RD_BYTE] & RD_MASK) != 0
    }

    /// Sets or clears the RD (recursion desired) bit.
    pub fn set_rd(&mut self, rd: bool) {
        if rd {
            self.octets[RD_BYTE] |= RD_MASK;
        } else {
            self.octets[RD_BYTE] &= !RD_MASK;
        }
    }

    /// Returns the current value of the RA (recursion available) bit.
    pub fn ra(&self) -> bool {
        (self.octets[RA_BYTE] & RA_MASK) != 0
    }

    /// Sets or clears the RA (recursion available) bit.
    pub fn set_ra(&mut self, ra: bool) {
        if ra {
            self.octets[RA_BYTE] |= RA_MASK;
        } else {
            self.octets[RA_BYTE] &= !RA_MASK;
        }
    }

    /// Returns the message's current RCODE. Note that if EDNS may be in
    /// use, one should use [`Writer::extended_rcode`] instead.
    pub fn rcode(&self) -> Rcode {
        let raw = self.octets[RCODE_BYTE] & RCODE_MASK;
        raw.try_into().unwrap()
    }

    /// Sets the message's RCODE. In an EDNS message, this clears the
    /// 8-bit extension of the RCODE in the OPT TTL field.
    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.octets[RCODE_BYTE] &= !RCODE_MASK;
        self.octets[RCODE_BYTE] |= u8::from(rcode);
        if let Some(ref mut edns) = self.edns {
            edns.extended_rcode_upper_bits = 0;
        }
    }

    /// Returns the message's extended RCODE. If EDNS is not in use,
    /// then this is just the RCODE.
    pub fn extended_rcode(&self) -> ExtendedRcode {
        let lower_four = (self.octets[RCODE_BYTE] & RCODE_MASK) as u16;
        if let Some(ref edns) = self.edns {
            let raw = ((edns.extended_rcode_upper_bits as u16) << 4) | lower_four;
            raw.into()
        } else {
            lower_four.into()
        }
    }

    /// Sets the message's extended RCODE. This will fail is EDNS is not
    /// in use, or if the value is greater than 4,095 (since OPT records
    /// can only express extended RCODEs that fit in 12 bits).
    pub fn set_extended_rcode(&mut self, rcode: ExtendedRcode) -> Result<()> {
        if let Some(ref mut edns) = self.edns {
            let raw = u16::from(rcode);
            if raw > 4095 {
                Err(Error::ExtendedRcodeOverflow)
            } else {
                self.octets[RCODE_BYTE] &= !RCODE_MASK;
                self.octets[RCODE_BYTE] |= (raw as u8) & RCODE_MASK;
                edns.extended_rcode_upper_bits = (raw >> 4) as u8;
                Ok(())
            }
        } else {
            Err(Error::NotEdns)
        }
    }

    /// Returns the current number of questions in the message.
    pub fn qdcount(&self) -> u16 {
        self.qdcount
    }

    /// Returns the current number of answer RRs in the message.
    pub fn ancount(&self) -> u16 {
        self.ancount
    }

    /// Returns the current number of authority RRs in the message.
    pub fn nscount(&self) -> u16 {
        self.nscount
    }

    /// Returns the current number of additional RRs in the message.
    pub fn arcount(&self) -> u16 {
        self.arcount
    }

    /// Adds a question to message. This must be used before any
    /// resource records are added.
    pub fn add_question(&mut self, question: &Question) -> Result<()> {
        if self.section != Section::Question {
            Err(Error::OutOfOrder)
        } else if let Some(new_qdcount) = self.qdcount.checked_add(1) {
            self.with_rollback(|this| {
                let qname = this.write_unhinted_name(&question.qname)?;
                if this.qdcount == 0 {
                    this.qname = qname;
                }
                this.try_push_u16(question.qtype.into())?;
                this.try_push_u16(question.qclass.into())
            })?;
            self.qdcount = new_qdcount;
            self.rr_start = self.cursor;
            Ok(())
        } else {
            Err(Error::CountOverflow)
        }
    }

    /// Adds a resource record to the answer section of the message.
    /// This must be used after any questions are added and before
    /// RRs are added to any other section. [`HintPointer`]s for domain
    /// names in the RDATA are written to the [`HintPointerVec`] if it
    /// is provided.
    pub fn add_answer_rr(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_answer()?;
            this.add_rr(owner, rr_type, class, ttl, rdata, hint_pointer_vec)?;
            if let Some(new_ancount) = this.ancount.checked_add(1) {
                this.ancount = new_ancount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Adds an RRset to the answer section of the message. This must be
    /// used after any questions are added and before RRs are added to
    /// any other section. [`HintPointer`]s for domain names in the
    /// RDATA are written to the [`HintPointerVec`] if it is provided.
    pub fn add_answer_rrset(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdatas: &RdataSet,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_answer()?;
            let n_added = this.add_rrset(owner, rr_type, class, ttl, rdatas, hint_pointer_vec)?;
            if n_added > u16::MAX as usize {
                Err(Error::CountOverflow)
            } else if let Some(new_ancount) = this.ancount.checked_add(n_added as u16) {
                this.ancount = new_ancount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Changes the current section to [`Section::Answer`], if possible.
    fn change_section_to_answer(&mut self) -> Result<()> {
        match self.section {
            Section::Question => {
                self.section = Section::Answer;
                Ok(())
            }
            Section::Answer => Ok(()),
            _ => Err(Error::OutOfOrder),
        }
    }

    /// Adds a resource record to the authority section of the message.
    /// This must be used after any questions and answer RRs are added
    /// and before any additional RRs are added. [`HintPointer`]s for
    /// domain names in the RDATA are written to the [`HintPointerVec`]
    /// if it is provided.
    pub fn add_authority_rr(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_authority()?;
            this.add_rr(owner, rr_type, class, ttl, rdata, hint_pointer_vec)?;
            if let Some(new_nscount) = this.nscount.checked_add(1) {
                this.nscount = new_nscount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Adds an RRset to the authority section of the message. This
    /// must be used after any questions and answer RRs are added and
    /// before any additional RRs are added. [`HintPointer`]s for domain
    /// names in the RDATA are written to the [`HintPointerVec`] if it
    /// is provided.
    pub fn add_authority_rrset(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdatas: &RdataSet,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_authority()?;
            let n_added = this.add_rrset(owner, rr_type, class, ttl, rdatas, hint_pointer_vec)?;
            if n_added > u16::MAX as usize {
                Err(Error::CountOverflow)
            } else if let Some(new_nscount) = this.nscount.checked_add(n_added as u16) {
                this.nscount = new_nscount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Changes the current section to [`Section::Authority`], if
    /// possible.
    fn change_section_to_authority(&mut self) -> Result<()> {
        match self.section {
            Section::Question | Section::Answer => {
                self.section = Section::Authority;
                Ok(())
            }
            Section::Authority => Ok(()),
            _ => Err(Error::OutOfOrder),
        }
    }

    /// Adds a resource record to the additional section of the message.
    /// This must be used after any questions and any RRs in other
    /// sections are added. [`HintPointer`]s for domain names in the
    /// RDATA are written to the [`HintPointerVec`] if it is provided.
    pub fn add_additional_rr(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.section = Section::Additional;
            this.add_rr(owner, rr_type, class, ttl, rdata, hint_pointer_vec)?;
            if let Some(new_arcount) = this.arcount.checked_add(1) {
                this.arcount = new_arcount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Adds an RRset to the additional section of the message. This
    /// must be used after any questions and any RRs in other sections
    /// are added. [`HintPointer`]s for domain names in the RDATA are
    /// written to the [`HintPointerVec`] if it is provided.
    pub fn add_additional_rrset(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdatas: &RdataSet,
        hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.section = Section::Additional;
            let n_added = this.add_rrset(owner, rr_type, class, ttl, rdatas, hint_pointer_vec)?;
            if n_added > u16::MAX as usize {
                Err(Error::CountOverflow)
            } else if let Some(new_arcount) = this.arcount.checked_add(n_added as u16) {
                this.arcount = new_arcount;
                Ok(())
            } else {
                Err(Error::CountOverflow)
            }
        })
    }

    /// Writes out an RR at the current cursor. This is for internal
    /// use: the write is not done atomically and may change the cursor
    /// even when an error is returned. This is intended by used with
    /// [`Writer::with_rollback`].
    fn add_rr(
        &mut self,
        owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
        mut hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<()> {
        self.most_recent_owner = self.write_hinted_name(owner)?;
        self.try_push_u16(rr_type.into())?;
        self.try_push_u16(class.into())?;
        self.try_push_u32(ttl.into())?;

        // Save two octets for the RDLENGTH field. We must compute and
        // write this field at the end, since it's affected by
        // compression.
        if self.available - self.cursor < 2 {
            return Err(Error::Truncation);
        }
        let rdlength_start = self.cursor;
        self.cursor += 2;

        // Write RDATA with compression.
        for component in rdata.components(rr_type) {
            let component = component.or(Err(Error::InvalidRdata))?;
            match component {
                Component::CompressibleName(name) => {
                    self.most_recent_name_in_rdata = self.write_unhinted_name(&name)?;
                    if let Some(hint_pointer_vec) = hint_pointer_vec.as_deref_mut() {
                        hint_pointer_vec.push(self.most_recent_name_in_rdata.map(|n| n.pointer));
                    }
                }
                Component::UncompressibleName(name) => {
                    self.most_recent_name_in_rdata = self.write_uncompressed_name(&name)?;
                    if let Some(hint_pointer_vec) = hint_pointer_vec.as_deref_mut() {
                        hint_pointer_vec.push(self.most_recent_name_in_rdata.map(|n| n.pointer));
                    }
                }
                Component::Other(octets) => self.try_push(octets)?,
            }
        }

        // Compute and write the RDLENTH field.
        let rdlength = self.cursor - rdlength_start - 2;
        self.write_u16(rdlength_start, rdlength as u16);
        Ok(())
    }

    /// Writes out an RRset at the current cursor. This is for internal
    /// use: the write is not done atomically and may change the cursor
    /// even when an error is returned. This is intended to be used with
    /// [`Writer::with_rollback`].
    fn add_rrset(
        &mut self,
        mut owner: HintedName,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdatas: &RdataSet,
        mut hint_pointer_vec: Option<&mut HintPointerVec>,
    ) -> Result<usize> {
        let mut n_added = 0;
        for rdata in rdatas.iter() {
            self.add_rr(
                owner,
                rr_type,
                class,
                ttl,
                rdata,
                hint_pointer_vec.as_deref_mut(),
            )?;
            owner.hint = Hint::MostRecentOwner;
            n_added += 1;
        }
        Ok(n_added)
    }

    /// Removes any resource records previously added to the message.
    pub fn clear_rrs(&mut self) {
        self.ancount = 0;
        self.nscount = 0;
        self.arcount = 0;
        if self.edns.is_some() {
            self.arcount += 1;
        }
        if self.tsig.is_some() {
            self.arcount += 1;
        }
        self.cursor = self.rr_start;
        self.section = Section::Question;
        self.most_recent_owner = None;
        self.most_recent_name_in_rdata = None;
    }

    /// Makes this an EDNS message. This will reserve space at the end
    /// of the message for the OPT record; if there is insufficient
    /// space, then this will fail. This will also fail if this is
    /// already an EDNS message.
    pub fn set_edns(&mut self, udp_payload_size: u16) -> Result<()> {
        if self.edns.is_some() {
            Err(Error::AlreadyEdns)
        } else if self.cursor + OPT_RECORD_SIZE > self.available {
            Err(Error::Truncation)
        } else if let Some(new_arcount) = self.arcount.checked_add(1) {
            self.arcount = new_arcount;
            self.available -= OPT_RECORD_SIZE;
            self.edns = Some(Edns {
                udp_payload_size,
                extended_rcode_upper_bits: 0,
            });
            Ok(())
        } else {
            Err(Error::CountOverflow)
        }
    }

    /// Makes this a TSIG-secured message. This will reserve space at
    /// the end of the message for the TSIG record; if there is
    /// insufficent space, then this will fail. This will also fail if
    /// this is already a TSIG message.
    pub fn set_tsig(&mut self, mode: TsigMode, rr: PreparedTsigRr) -> Result<()> {
        if self.tsig.is_some() {
            return Err(Error::AlreadyTsig);
        }

        let reserved_len = match &mode {
            TsigMode::Request { algorithm, .. }
            | TsigMode::Response { algorithm, .. }
            | TsigMode::Subsequent { algorithm, .. } => rr.signed_len(*algorithm),
            TsigMode::Unsigned { algorithm } => rr.unsigned_len(algorithm),
        };
        if self.cursor + reserved_len > self.available {
            Err(Error::Truncation)
        } else if let Some(new_arcount) = self.arcount.checked_add(1) {
            self.arcount = new_arcount;
            self.available -= reserved_len;
            self.tsig = Some(Tsig {
                mode,
                reserved_len,
                rr,
            });
            Ok(())
        } else {
            Err(Error::CountOverflow)
        }
    }

    /// Updates the TSIG "time signed" field. This will fail if TSIG has
    /// not been configured.
    pub fn update_time_signed(&mut self, time_signed: TimeSigned) -> Result<()> {
        if let Some(tsig) = &mut self.tsig {
            tsig.rr.time_signed = time_signed;
            Ok(())
        } else {
            Err(Error::NotTsig)
        }
    }

    /// Finishes writing the message. The final length of the message
    /// is returned.
    pub fn finish(self) -> usize {
        self.finish_with_mac().0
    }

    /// Finishes writing the message, returning its final length and
    /// its TSIG MAC (if the message was signed).
    pub fn finish_with_mac(mut self) -> (usize, Option<Box<[u8]>>) {
        self.write_u16(QDCOUNT_START, self.qdcount);
        self.write_u16(ANCOUNT_START, self.ancount);
        self.write_u16(NSCOUNT_START, self.nscount);
        self.write_u16(ARCOUNT_START, self.arcount);

        // We finish up by writing any OPT or TSIG records that need to
        // go at the end of the message. (In particular, TSIG *must* be
        // the last record in the message, since it carries a signature
        // for everything that preceded it.) In each case, before we
        // write the RR, we need to update the "available" field to undo
        // the space reservation we made for the RR, since
        // Reader::add_rr checks it. The unwraps after Reader::add_rr
        // are okay, since (through the reservation) we've ensured that
        // there will be enough space.

        if let Some(ref edns) = self.edns {
            let class = Class::from(edns.udp_payload_size);
            let ttl = Ttl::from((edns.extended_rcode_upper_bits as u32) << 24);
            self.available += OPT_RECORD_SIZE;
            self.add_rr(
                HintedName::new(Hint::None, Name::root()),
                Type::OPT,
                class,
                ttl,
                Rdata::empty(),
                None,
            )
            .unwrap();
        }

        let mac = if let Some(tsig) = self.tsig.take() {
            let message = &self.octets[0..self.cursor];
            let (rdata, mac) = match &tsig.mode {
                TsigMode::Request { algorithm, key } => {
                    let (rdata, mac) = tsig.rr.sign_request(message, *algorithm, key);
                    (rdata, Some(mac))
                }
                TsigMode::Response {
                    request_mac,
                    algorithm,
                    key,
                } => {
                    let (rdata, mac) = tsig.rr.sign_response(message, request_mac, *algorithm, key);
                    (rdata, Some(mac))
                }
                TsigMode::Subsequent {
                    prior_mac,
                    algorithm,
                    key,
                } => {
                    let (rdata, mac) = tsig.rr.sign_subsequent(message, prior_mac, *algorithm, key);
                    (rdata, Some(mac))
                }
                TsigMode::Unsigned { algorithm } => (tsig.rr.unsigned(algorithm), None),
            };
            self.available += tsig.reserved_len;
            self.add_rr(
                HintedName::new(Hint::None, &tsig.rr.key_name),
                Type::TSIG,
                Qclass::ANY.into(),
                Ttl::from(0),
                &rdata,
                None,
            )
            .unwrap();
            mac
        } else {
            None
        };

        (self.cursor, mac)
    }

    /// Executes `f(self)`, returning the result and rolling back the
    /// section, cursor, and compression state to the current values
    /// first if the result is an error.
    fn with_rollback<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let saved_section = self.section;
        let saved_cursor = self.cursor;
        let saved_qname = self.qname;
        let saved_most_recent_owner = self.most_recent_owner;
        let saved_most_recent_name_in_rdata = self.most_recent_name_in_rdata;
        let result = f(self);
        if result.is_err() {
            self.section = saved_section;
            self.cursor = saved_cursor;
            self.qname = saved_qname;
            self.most_recent_owner = saved_most_recent_owner;
            self.most_recent_name_in_rdata = saved_most_recent_name_in_rdata;
        }
        result
    }

    /// Writes a domain name to the underlying buffer at the current
    /// cursor, compressing it based on the provided hint if compression
    /// is enabled and if the name is long enough to make it worthwhile.
    fn write_hinted_name(&mut self, hinted_name: HintedName) -> Result<Option<PriorName>> {
        // Compression is not worth it if the name is no longer than a
        // two-octet pointer.
        if self.compression_mode == CompressionMode::Disabled
            || hinted_name.name.wire_repr().len() <= 2
        {
            return self.write_uncompressed_name(hinted_name.name);
        }

        // The hints API doesn't require that the prior occurrence
        // specified by the hint be equal case-sensitively. Therefore,
        // we don't use hints in case-preserving compression mode.
        if self.compression_mode == CompressionMode::CasePreserving {
            return self.write_compressed_unhinted_name(hinted_name.name);
        }

        match hinted_name.hint {
            Hint::Qname => {
                if let Some(qname) = self.qname {
                    self.try_push_u16(0xc000 | qname.pointer.get())
                        .and(Ok(Some(qname)))
                } else {
                    self.write_compressed_unhinted_name(hinted_name.name)
                }
            }
            Hint::MostRecentOwner => {
                if let Some(most_recent_owner) = self.most_recent_owner {
                    self.try_push_u16(0xc000 | most_recent_owner.pointer.get())
                        .and(Ok(Some(most_recent_owner)))
                } else {
                    self.write_compressed_unhinted_name(hinted_name.name)
                }
            }
            Hint::MostRecentNameInRdata => {
                if let Some(most_recent_name_in_rdata) = self.most_recent_name_in_rdata {
                    self.try_push_u16(0xc000 | most_recent_name_in_rdata.pointer.get())
                        .and(Ok(Some(most_recent_name_in_rdata)))
                } else {
                    self.write_compressed_unhinted_name(hinted_name.name)
                }
            }
            Hint::Explicit(pointer) => {
                if (pointer.get() as usize) < self.cursor {
                    self.try_push_u16(0xc000 | pointer.get())
                        .and(Ok(Some(PriorName::new(pointer, hinted_name.name))))
                } else {
                    self.write_compressed_unhinted_name(hinted_name.name)
                }
            }
            Hint::None => self.write_compressed_unhinted_name(hinted_name.name),
        }
    }

    /// Writes a domain name without a hint to the underlying buffer at
    /// the current cursor, trying to compress it if compression is
    /// enabled and if the name is long enough to make it worthwhile.
    fn write_unhinted_name(&mut self, name: &Name) -> Result<Option<PriorName>> {
        // Compression is not worth it if the name is no longer than a
        // two-octet pointer.
        if self.compression_mode != CompressionMode::Disabled && name.wire_repr().len() > 2 {
            self.write_compressed_unhinted_name(name)
        } else {
            self.write_uncompressed_name(name)
        }
    }

    /// Writes a domain name to the underlying buffer at the current
    /// cursor, always trying to compress it (even if compression is
    /// disabled or if the name is too short to make it worthwhile).
    fn write_compressed_unhinted_name(&mut self, compressee: &Name) -> Result<Option<PriorName>> {
        // An authoritative server can generally provide compression
        // hints for many of the record owners it writes to a message.
        // Thus, it's more likely than not that we're being asked to
        // compress a name in RDATA. Where might a similar name have
        // already been written? Multi-record RRsets that contain domain
        // names, for instance multi-record NS and MX RRsets, likely
        // contain many *similar* names. Thus, there's a good chance
        // that the name most recently written in RDATA is a similar
        // name. Furthermore, there's a fair chance that the name is
        // within the same zone as the record owner, e.g. an in-zone
        // CNAME. Thus we can guess that the most recently written
        // record owner or the QNAME are similar.
        //
        // It's still possible that we're asked to compress a record
        // owner. For an authoritative server, it's very likely that
        // the record owner is in the same zone as other record owners
        // in the message or the QNAME, so we expect these to be
        // similar. In particular, iteration algorithms for zone data
        // structures often emit records of the same or similar names
        // near one another. Thus, while AXFR does not *require* any
        // particular record order, it's likely that RRs will be written
        // such that the next record owner is equal to or very close to
        // the last.
        //
        // To summarize, the name we're asked to write is probably close
        // to the most recently written name in RDATA, the most recently
        // written record owner, or the QNAME.
        //
        // Furthermore, for an authoritative server, it makes sense to
        // prioritize the most recent owner over the QNAME. For a
        // referral response for a delegation with in-zone name servers,
        // the domain names in the RDATA will be subdomains of the
        // record owner. Additionally, as explained above, using the
        // most recent owner is effective with AXFR.
        //
        // On the basis of this analysis, and with a desire to make
        // message serialization fast, we'll elect not to perform
        // perfect compression. Instead, like Knot, we'll rely on
        // heuristics. To avoid too much work, we'll try to compress the
        // name against no more than two previously written names. Per
        // the discussion above, those two should be (1) the most
        // recently written owner, with the QNAME as a fallback; and (2)
        // the name most recently written in RDATA. We'll do this by
        // conceptually "lining up" the labels of the prior name(s) with
        // those of the current name (the "compressee," if you will), as
        // pictured:
        //
        // Column number:           -2  -1   0      1     2    3
        //                       .---------------------------------
        // Compressee:           |          www  example com (null)
        // Most recent owner:    |               example com (null)
        // Most recent in RDATA: | just one more example net (null)
        //
        // We then scan from left to right, starting with the column
        // containing the compressee's first label (column 0). If the
        // labels of a prior name start to match the compressee's, then
        // we make a note of it. If they stop matching, then we clear
        // our record of the match. At the end, we see if any matches
        // are active. If so, then we compress using the longest one.
        // During this whole process, the prior names are read directly
        // from the message written so far.
        //
        // Let's get to it then!

        // This structure keeps track of a single prior name that we're
        // trying to compress against.
        struct PriorCtx {
            start_column: usize,
            pointer: usize,
            match_start: Option<MatchStart>,
        }

        // This structure keeps track of an active match against a prior
        // name.
        struct MatchStart {
            start_column: usize,
            prior_pointer: HintPointer,
        }

        // This advances a pointer to a label in a prior name until it's
        // at the next "real" (i.e., non-pointer) label.
        let move_to_next_real_label = |pointer: &mut usize| loop {
            let len = self.octets[*pointer] as usize;
            if len & 0xc0 == 0xc0 {
                let next_pointer = ((len & 0x3f) << 8) | (self.octets[*pointer + 1] as usize);
                if next_pointer < *pointer {
                    *pointer = next_pointer;
                } else {
                    panic!("invalid pointer found during compression; this is a bug");
                }
            } else {
                return;
            }
        };

        // This sets up the PriorCtx for a prior name. If the prior name
        // is longer than the compressee, then we skip through labels
        // until we get to the one that is in "column 0" per the diagram
        // above.
        let build_prior_ctx = |prior: PriorName| {
            let prior_len = prior.len as usize;
            let start_column = compressee.len().saturating_sub(prior_len);
            let mut prior_pointer = prior.pointer.get() as usize;
            if prior_len > compressee.len() {
                let skip = prior_len - compressee.len();
                for _ in 0..skip {
                    // Writer code is careful not to store a pointer to
                    // a label that is itself a pointer. Thus we'll
                    // assume in the first iteration that prior_pointer
                    // points to a real label.
                    let label_len = self.octets[prior_pointer] as usize;
                    prior_pointer += label_len + 1;
                    move_to_next_real_label(&mut prior_pointer);
                }
            }
            PriorCtx {
                start_column,
                pointer: prior_pointer,
                match_start: None,
            }
        };

        // Load the prior names.
        let most_recent_owner_or_qname = self.most_recent_owner.or(self.qname);
        if most_recent_owner_or_qname.is_none() && self.most_recent_name_in_rdata.is_none() {
            return self.write_uncompressed_name(compressee);
        }
        let mut prior_ctxs = [
            most_recent_owner_or_qname.map(build_prior_ctx),
            self.most_recent_name_in_rdata.map(build_prior_ctx),
        ];

        // And here's the scan, finally!
        for (column, compressee_label) in compressee.labels().take(compressee.len() - 1).enumerate()
        {
            // It often happens that both prior names eventually point
            // back to the same place in the message. In that case, we
            // can eliminate one to avoid doing the same thing twice.
            if let (Some(a), Some(b)) = (&prior_ctxs[0], &prior_ctxs[1]) {
                if a.pointer == b.pointer {
                    match (&a.match_start, &b.match_start) {
                        (Some(a), Some(b)) => {
                            if a.start_column <= b.start_column {
                                prior_ctxs[1] = None;
                            } else {
                                prior_ctxs[0] = None;
                            }
                        }
                        (Some(_), None) => prior_ctxs[1] = None,
                        (None, Some(_)) => prior_ctxs[0] = None,
                        (None, None) => prior_ctxs[1] = None,
                    }
                }
            }

            for prior_ctx in &mut prior_ctxs {
                let prior_ctx = match prior_ctx.as_mut() {
                    Some(p) => p,
                    None => continue,
                };
                if column < prior_ctx.start_column {
                    continue;
                }

                let prior_label_len = self.octets[prior_ctx.pointer] as usize;
                let prior_label_octets =
                    &self.octets[prior_ctx.pointer + 1..prior_ctx.pointer + 1 + prior_label_len];
                if let Some(prior_pointer) = HintPointer::new(prior_ctx.pointer) {
                    let labels_equal = if self.compression_mode == CompressionMode::CasePreserving {
                        compressee_label.octets() == prior_label_octets
                    } else {
                        compressee_label
                            .octets()
                            .eq_ignore_ascii_case(prior_label_octets)
                    };
                    if labels_equal {
                        prior_ctx.match_start.get_or_insert(MatchStart {
                            start_column: column,
                            prior_pointer,
                        });
                    } else {
                        prior_ctx.match_start = None;
                    }
                } else {
                    // This case shouldn't actually happen, since we
                    // only store prior names when they're early enough
                    // in the message to be referenced.
                    prior_ctx.match_start = None;
                }

                prior_ctx.pointer += 1 + prior_label_len;
                move_to_next_real_label(&mut prior_ctx.pointer);
            }
        }

        let longest_match = prior_ctxs
            .iter()
            .filter_map(|pc_opt| pc_opt.as_ref().and_then(|pc| pc.match_start.as_ref()))
            .fold(None, |longest_so_far: Option<&MatchStart>, next| {
                Some(longest_so_far.map_or(next, |longest_so_far| {
                    if next.start_column < longest_so_far.start_column {
                        next
                    } else {
                        longest_so_far
                    }
                }))
            });

        if let Some(longest_match) = longest_match {
            if longest_match.start_column == 0 {
                self.try_push_u16(0xc000 | longest_match.prior_pointer.get())?;
                Ok(Some(PriorName::new(
                    longest_match.prior_pointer,
                    compressee,
                )))
            } else {
                let pointer = HintPointer::new(self.cursor);
                self.try_push(compressee.wire_repr_to(longest_match.start_column))?;
                self.try_push_u16(0xc000 | longest_match.prior_pointer.get())?;
                Ok(pointer.map(|pointer| PriorName::new(pointer, compressee)))
            }
        } else {
            self.write_uncompressed_name(compressee)
        }
    }

    /// Writes a domain name to the underlying buffer at the current
    /// cursor, without compression.
    fn write_uncompressed_name(&mut self, name: &Name) -> Result<Option<PriorName>> {
        let pointer = HintPointer::new(self.cursor);
        self.try_push(name.wire_repr())?;
        Ok(pointer.map(|pointer| PriorName::new(pointer, name)))
    }

    /// Tries to write `data` to the underlying buffer at the current
    /// cursor, failing if there is not sufficient space.
    fn try_push(&mut self, data: &[u8]) -> Result<()> {
        if self.available - self.cursor >= data.len() {
            self.write(self.cursor, data);
            self.cursor += data.len();
            Ok(())
        } else {
            Err(Error::Truncation)
        }
    }

    /// Tries to write `data` in network byte order to the underlying
    /// buffer, failing if there is not sufficient space.
    fn try_push_u16(&mut self, data: u16) -> Result<()> {
        self.try_push(&data.to_be_bytes())
    }

    /// Tries to write `data` in network byte order to the underlying
    /// buffer, failing if there is not sufficient space.
    fn try_push_u32(&mut self, data: u32) -> Result<()> {
        self.try_push(&data.to_be_bytes())
    }

    /// Writes `data` to the underlying buffer at `position`. Note that
    /// this performs no bounds checking.
    fn write(&mut self, position: usize, data: &[u8]) {
        self.octets[position..position + data.len()].copy_from_slice(data);
    }

    /// Writes `data` in network byte order to the underlying buffer at
    /// `position`. Note that this performs no bounds checking.
    fn write_u16(&mut self, position: usize, data: u16) {
        self.write(position, &data.to_be_bytes());
    }
}

impl<'a> TryFrom<&'a mut [u8]> for Writer<'a> {
    type Error = Error;

    fn try_from(octets: &'a mut [u8]) -> Result<Self> {
        Self::new(octets, octets.len())
    }
}

////////////////////////////////////////////////////////////////////////
// HINTED NAMES                                                       //
////////////////////////////////////////////////////////////////////////

/// A domain name combined with a hint for compression in a DNS message.
///
/// The DNS protocol allows domain names in certain fields in messages
/// optionally to be compressed using an ad-hoc compression scheme. To
/// take advantage of this, the [`Writer`] API accepts a [`HintedName`]
/// to specify the record owner when writing resource records. This
/// structure combines a reference to a [`Name`] with a [`Hint`] that
/// informs the [`Writer`] where the name has occurred previously in the
/// the message.
///
/// When using a hint, the caller promises that the hint is correct. The
/// [`Writer`] does check that the prior occurrence exists; for example,
/// it will not compress using [`Hint::Qname`] if no question has been
/// written to the message. However, it *does not* check that the prior
/// occurrence is the same as the name provided in the `HintedName`. For
/// instance, passing a `HintedName` with [`Hint::Qname`] and a name
/// that is *not* the QNAME may produce incorrect results.
///
/// Using [`Hint::None`] will always produce correct results.
#[derive(Clone, Copy, Debug)]
pub struct HintedName<'a> {
    hint: Hint,
    name: &'a Name,
}

impl<'a> HintedName<'a> {
    /// Creates a new `HintedName` from the provided hint and name.
    pub const fn new(hint: Hint, name: &'a Name) -> Self {
        Self { hint, name }
    }

    /// Creates a new `HintedName`, generating the hint from the
    /// specified [`HintPointer`] in a [`HintPointerVec`] if available
    /// and using [`Hint::None`] otherwise.
    pub fn from_hint_pointer_vec(
        hint_pointer_vec: &HintPointerVec,
        index: usize,
        name: &'a Name,
    ) -> Self {
        Self {
            hint: hint_pointer_vec
                .get(index)
                .map_or(Hint::None, Hint::Explicit),
            name,
        }
    }

    /// Creates a new `HintedName`, generating the hint from the
    /// specified [`HintPointer`] in a [`HintPointerVec`] if a vector
    /// is provided and the hint is available. [`Hint::None`] is used
    /// otherwise.
    pub fn from_hint_pointer_vec_opt(
        hint_pointer_vec: Option<&HintPointerVec>,
        index: usize,
        name: &'a Name,
    ) -> Self {
        Self {
            hint: hint_pointer_vec
                .and_then(|ha| ha.get(index))
                .map_or(Hint::None, Hint::Explicit),
            name,
        }
    }

    /// Returns the [`Hint`] associated with this `HintedName`.
    pub const fn hint(self) -> Hint {
        self.hint
    }

    /// Returns the [`Name`] associated with this `HintedName`.
    pub const fn name(self) -> &'a Name {
        self.name
    }
}

/// A hint for how to compress a domain name in a DNS message.
///
/// See [`HintedName`] for more information.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Hint {
    /// The name is the QNAME in the (first) question of the message.
    Qname,

    /// The name is the same as the owner of the resource record most
    /// recently added to the message.
    MostRecentOwner,

    /// The name is the most recent domain name known to have been
    /// written embedded in RDATA.
    ///
    /// Note that names embedded in RDATA of TYPEs unknown to Quandary
    /// are not detected. As support for new TYPEs is added, [`Writer`]
    /// may begin to detect previously undetected names. Therefore, be
    /// careful to use this hint only when you can prove that such
    /// developments will not affect this hint's behavior.
    MostRecentNameInRdata,

    /// The name was previously written at a recorded location; use the
    /// provided pointer.
    Explicit(HintPointer),

    /// No hint is provided.
    None,
}

/// An explicit pointer to use to compress a domain name.
///
/// A `HintPointer` is used to record where a name was previously
/// written, so that (in conjunction with [`Hint::Explicit`]) subsequent
/// instances of the name can be compressed simply by copying the
/// pointer. Currently, the only way to obtain a `HintPointer` is to use
/// [`Writer`] methods that generate them. They are generally delivered
/// to the caller by pushing them into a caller-provided
/// [`HintPointerVec`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HintPointer(NonZeroU16);

impl HintPointer {
    /// Creates a new `HintPointer`. This will return `None` for zero
    /// values or values that are greater than [`POINTER_MAX`].
    const fn new(cursor: usize) -> Option<Self> {
        if cursor <= POINTER_MAX {
            if let Some(nonzero) = NonZeroU16::new(cursor as u16) {
                Some(Self(nonzero))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the pointer's value.
    const fn get(self) -> u16 {
        self.0.get()
    }
}

/// The maximum number of pointers that fit in a [`HintPointerVec`]. The
/// current value is chosen so that we will not run out of room when
/// writing the root's NS RRset.
const HINT_POINTER_VEC_SIZE: usize = 16;

/// An array-backed vector of [`HintPointer`]s.
///
/// [`Writer`] methods that provide the caller with [`HintPointer`]s for
/// domain names that they write may do so by pushing them into a
/// `HintPointerVec`. This structure is backed by a fixed-size array and
/// is suitable for stack allocation. This means that a
/// [`HintPointerVec`] may not be able to hold all hints generated.
/// Hints that do not fit are silently dropped. The array size is
/// calibrated so that it will not fill up for most use cases.
#[derive(Clone, Debug, Default)]
pub struct HintPointerVec {
    inner: ArrayVec<Option<HintPointer>, { HINT_POINTER_VEC_SIZE }>,
}

impl HintPointerVec {
    /// Constructs a new `HintPointerVec`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets an entry from the vector.
    ///
    /// Note that if no [`HintPointer`] is available for index `n`, it
    /// does *not* follow that none is available for index `n + 1`.
    pub fn get(&self, index: usize) -> Option<HintPointer> {
        self.inner.get(index).copied().flatten()
    }

    /// Pushes an entry if space remains in the vector. The value is
    /// silently discarded if not.
    fn push(&mut self, pointer: Option<HintPointer>) {
        let _ = self.inner.try_push(pointer);
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error signaling that a [`Writer`] operation could not be
/// performed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    /// Adding the question or resource record(s) would overflow the
    /// corresponding 16-bit counter in the DNS header.
    CountOverflow,

    /// There is not enough room left in the buffer.
    Truncation,

    /// An attempt was made to serialize a question or resource record
    /// in the wrong place in the message (e.g., adding a question after
    /// an answer resource record has already been serialized).
    OutOfOrder,

    /// The operation required parsing of RDATA, and it was found to be
    /// invalid.
    InvalidRdata,

    /// An attempt was made to set EDNS parameters on a non-EDNS
    /// message.
    NotEdns,

    /// An attempt was made to set up EDNS when EDNS is already enabled.
    AlreadyEdns,

    /// An attempt was made to set an extended RCODE over 4,095.
    ExtendedRcodeOverflow,

    /// An attempt was made to made to set TSIG parameters on a non-TSIG
    /// message.
    NotTsig,

    /// An attempt was made to set up TSIG, but TSIG is already enabled.
    AlreadyTsig,

    /// The operation requires TSIG to be enabled and configured for one
    /// the signing modes.
    NotSignedTsig,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::CountOverflow => f.write_str("record count would overflow"),
            Self::Truncation => f.write_str("message would be truncated"),
            Self::OutOfOrder => f.write_str("question or record serialized out of order"),
            Self::InvalidRdata => f.write_str("invalid RDATA"),
            Self::NotEdns => f.write_str("not an EDNS message"),
            Self::AlreadyEdns => f.write_str("already an EDNS message"),
            Self::ExtendedRcodeOverflow => f.write_str("extended RCODE would overflow"),
            Self::NotTsig => f.write_str("not a TSIG message"),
            Self::AlreadyTsig => f.write_str("already a TSIG message"),
            Self::NotSignedTsig => f.write_str("not a signed TSIG message"),
        }
    }
}

impl std::error::Error for Error {}

/// The type returned by fallible [`Writer`] methods.
pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    // NOTE: tests for TSIG signing with Writer are located with the
    // main TSIG implementation in tsig.rs.

    use lazy_static::lazy_static;

    use super::super::Question;
    use super::*;
    use crate::rr::rdata::TimeSigned;
    use crate::rr::RdataSetOwned;

    static TYPE: Type = Type::A;
    static CLASS: Class = Class::IN;

    lazy_static! {
        static ref NAME: Box<Name> = "quandary.test.".parse().unwrap();
        static ref HINTED_NAME: HintedName<'static> = HintedName::new(Hint::None, &NAME);
        static ref QUESTION: Question = Question {
            qname: NAME.clone(),
            qtype: Type::A.into(),
            qclass: Class::IN.into(),
        };
        static ref TTL: Ttl = Ttl::from(3600);
        static ref RDATA: &'static Rdata = b"\x7f\x00\x00\x01".try_into().unwrap();
        static ref RDATAS: RdataSetOwned = (*RDATA).into();
        static ref TSIG_MODE: TsigMode = TsigMode::Unsigned {
            algorithm: Algorithm::HmacSha256.name().to_owned(),
        };
        static ref TSIG_RR: PreparedTsigRr = {
            let time_signed = TimeSigned::try_from_unix_time(0).unwrap();
            PreparedTsigRr {
                key_name: "a.tsig.key.".parse().unwrap(),
                time_signed,
                fudge: 300,
                original_id: 0,
                error: ExtendedRcode::NOERROR,
                server_time: time_signed,
            }
        };
    }

    #[test]
    fn writer_works() {
        // This is not meant to be exhaustive by any means. Rather, it's
        // just a check that the Writer works in a basic scenario.
        let mut buf = vec![0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_id(0x0703);
        writer.set_opcode(Opcode::QUERY);
        writer.set_qr(true);
        writer.set_aa(true);
        writer.set_rcode(Rcode::NOERROR);
        writer.add_question(&QUESTION).unwrap();
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x07\x03\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x01\x00\x01\
              \xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01"
        );
    }

    #[test]
    fn writer_works_with_edns() {
        // Again, this is not meant to be exhaustive—just a check that
        // basic EDNS operations work.
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_id(0x0703);
        writer.set_opcode(Opcode::UPDATE);
        writer.set_qr(true);
        writer.set_edns(1232).unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x07\x03\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x01\
              \x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00",
        );
    }

    #[test]
    fn writer_detects_qdcount_overflow() {
        let mut buf = vec![0; 2_097_152]; // 2 MiB
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        for _ in 0..u16::MAX {
            writer.add_question(&QUESTION).unwrap();
        }
        assert_eq!(writer.add_question(&QUESTION), Err(Error::CountOverflow));
    }

    #[test]
    fn writer_detects_rr_count_overflows() {
        let mut buf = vec![0; 2_097_152]; // 2 MiB
        rr_count_overflow_test_impl(&mut buf, Writer::add_answer_rr, Writer::add_answer_rrset);
        rr_count_overflow_test_impl(
            &mut buf,
            Writer::add_authority_rr,
            Writer::add_authority_rrset,
        );
        rr_count_overflow_test_impl(
            &mut buf,
            Writer::add_additional_rr,
            Writer::add_additional_rrset,
        );
    }

    fn rr_count_overflow_test_impl<'a>(
        buf: &'a mut [u8],
        add_rr: AddRr<'a>,
        add_rrset: AddRrset<'a>,
    ) {
        let mut writer = Writer::try_from(buf).unwrap();
        for _ in 0..u16::MAX {
            add_rrset(&mut writer, *HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None).unwrap();
        }
        assert_eq!(
            add_rr(&mut writer, *HINTED_NAME, TYPE, CLASS, *TTL, &RDATA, None),
            Err(Error::CountOverflow),
        );
        assert_eq!(
            add_rrset(&mut writer, *HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None),
            Err(Error::CountOverflow),
        );
    }

    type AddRr<'a> = fn(
        &mut Writer<'a>,
        HintedName,
        Type,
        Class,
        Ttl,
        &Rdata,
        Option<&mut HintPointerVec>,
    ) -> Result<()>;

    type AddRrset<'a> = fn(
        &mut Writer<'a>,
        HintedName,
        Type,
        Class,
        Ttl,
        &RdataSet,
        Option<&mut HintPointerVec>,
    ) -> Result<()>;

    #[test]
    fn writer_enforces_question_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Question.
        writer.add_question(&QUESTION).unwrap();

        // Check Question -> Question.
        writer.add_question(&QUESTION).unwrap();

        // Check Answer -> Question.
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));

        // Check Authority -> Question.
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));

        // Check Additional -> Question.
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));
    }

    #[test]
    fn writer_enforces_answer_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Answer.
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Answer -> Answer.
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Question -> Answer.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Authority -> Answer.
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(
            writer.add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None),
            Err(Error::OutOfOrder),
        );

        // Check Additional -> Answer.
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(
            writer.add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None),
            Err(Error::OutOfOrder),
        );
    }

    #[test]
    fn writer_enforces_authority_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Authority.
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Authority -> Authority.
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Question -> Authority.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Answer -> Authority.
        writer.clear_rrs();
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Additional -> Authority.
        writer.clear_rrs();
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        assert_eq!(
            writer.add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None),
            Err(Error::OutOfOrder),
        );
    }

    #[test]
    fn writer_enforces_additional_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Additional.
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Additional -> Additional.
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Question -> Additional.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Answer -> Additional.
        writer.clear_rrs();
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();

        // Check Authority -> Additional.
        writer.clear_rrs();
        writer
            .add_authority_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        writer
            .add_additional_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
    }

    #[test]
    fn writer_constructors_reject_short_buffers() {
        let mut big_buf = [0; 512];
        for size in 0..HEADER_SIZE {
            let mut exact_buf = vec![0; size];
            assert!(matches!(
                Writer::new(big_buf.as_mut_slice(), size),
                Err(Error::Truncation),
            ));
            assert!(matches!(
                Writer::try_from(exact_buf.as_mut_slice()),
                Err(Error::Truncation),
            ));
        }
    }

    #[test]
    fn set_limit_works() {
        let mut buf = [0; 1024];
        let mut writer = Writer::new(buf.as_mut_slice(), 512).unwrap();
        writer.available = 256;
        writer.set_limit(768);
        assert_eq!(writer.limit, 768);
        assert_eq!(writer.available, 512);
        writer.set_limit(512);
        assert_eq!(writer.limit, 512);
        assert_eq!(writer.available, 256);
    }

    #[test]
    fn set_limit_caps_at_buffer_len() {
        let mut buf = [0; 1024];
        let mut writer = Writer::new(buf.as_mut_slice(), 512).unwrap();
        writer.set_limit(2048);
        assert_eq!(writer.limit, 1024);
    }

    #[test]
    fn set_limit_respects_existing_data_and_reserved_octets() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.available = 384; // Reserves 512 - 384 = 128 octets.
        writer.set_limit(0);
        assert_eq!(writer.limit, 140); // 12 octets for the message header + 128 octets reserved.
        assert_eq!(writer.available, 12);
    }

    #[test]
    fn set_edns_fails_if_repeated() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_edns(512).unwrap();
        assert_eq!(writer.set_edns(512), Err(Error::AlreadyEdns));
    }

    #[test]
    fn set_tsig_fails_if_repeated() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_tsig(TSIG_MODE.clone(), TSIG_RR.clone()).unwrap();
        assert_eq!(
            writer.set_tsig(TSIG_MODE.clone(), TSIG_RR.clone()),
            Err(Error::AlreadyTsig),
        );
    }

    #[test]
    fn set_rcode_zeroes_extended_rcode_upper_bits() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_edns(512).unwrap();
        writer
            .set_extended_rcode(ExtendedRcode::BADVERSBADSIG)
            .unwrap();
        writer.set_rcode(Rcode::NOERROR);
        assert_eq!(writer.extended_rcode(), ExtendedRcode::NOERROR);
    }

    #[test]
    fn extended_rcodes_work() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_edns(512).unwrap();
        writer.set_extended_rcode(ExtendedRcode::BADCOOKIE).unwrap();
        assert_eq!(writer.extended_rcode(), ExtendedRcode::BADCOOKIE);
    }

    #[test]
    fn extended_rcode_works_without_edns() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_rcode(Rcode::SERVFAIL);
        assert_eq!(writer.extended_rcode(), ExtendedRcode::SERVFAIL);
    }

    #[test]
    fn set_extended_rcode_fails_if_not_edns() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        assert_eq!(
            writer.set_extended_rcode(ExtendedRcode::NOERROR),
            Err(Error::NotEdns),
        );
    }

    #[test]
    fn set_extended_rcode_fails_if_value_too_large() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_edns(512).unwrap();
        assert_eq!(
            writer.set_extended_rcode(4096.into()),
            Err(Error::ExtendedRcodeOverflow),
        );
    }

    #[test]
    fn qname_hint_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.add_question(&QUESTION).unwrap();
        let hinted_for_qname = HintedName::new(Hint::Qname, NAME.as_ref());
        writer
            .add_answer_rrset(hinted_for_qname, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x01\x00\x01\
              \xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn most_recent_owner_hint_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer
            .add_answer_rrset(*HINTED_NAME, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let hinted_for_mro = HintedName::new(Hint::MostRecentOwner, NAME.as_ref());
        writer
            .add_additional_rrset(hinted_for_mro, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\
              \x08quandary\x04test\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01\
              \xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn most_recent_name_in_rdata_hint_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        let cname: Box<Name> = "canonical.test.".parse().unwrap();
        let cname_rdata = cname.wire_repr().try_into().unwrap();
        writer
            .add_answer_rr(*HINTED_NAME, Type::CNAME, CLASS, *TTL, cname_rdata, None)
            .unwrap();
        let hinted_for_mrnir = HintedName::new(Hint::MostRecentNameInRdata, &cname);
        writer
            .add_answer_rrset(hinted_for_mrnir, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x0c\
              \x09canonical\xc0\x15\
              \xc0\x25\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn explicit_hint_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        let exchange: Box<Name> = "mx.quandary.test.".parse().unwrap();
        let rdata = Rdata::new_mx(10, &exchange);
        let mut hint_pointer_vec = HintPointerVec::new();
        writer
            .add_answer_rr(
                *HINTED_NAME,
                Type::MX,
                CLASS,
                *TTL,
                &rdata,
                Some(&mut hint_pointer_vec),
            )
            .unwrap();
        let explicitly_hinted = HintedName::from_hint_pointer_vec(&hint_pointer_vec, 0, &exchange);
        writer
            .add_additional_rrset(explicitly_hinted, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\
              \x08quandary\x04test\x00\x00\x0f\x00\x01\x00\x00\x0e\x10\x00\x07\
              \x00\x0a\x02mx\xc0\x0c\
              \xc0\x27\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn compression_can_be_disabled() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_compression_mode(CompressionMode::Disabled);
        writer.add_question(&QUESTION).unwrap();
        let hinted_for_qname = HintedName::new(Hint::Qname, NAME.as_ref());
        writer
            .add_answer_rrset(hinted_for_qname, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x01\x00\x01\
              \x08quandary\x04test\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn case_preserving_compression_works() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_compression_mode(CompressionMode::CasePreserving);
        writer.add_question(&QUESTION).unwrap();
        let different_case: Box<Name> = "Quandary.test.".parse().unwrap();
        let hinted_for_qname = HintedName::new(Hint::Qname, &different_case);
        writer
            .add_answer_rrset(hinted_for_qname, TYPE, CLASS, *TTL, &RDATAS, None)
            .unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x01\x00\x01\
              \x08Quandary\xc0\x15\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01",
        );
    }

    #[test]
    fn clear_rrs_keeps_pseudo_rrs() {
        let mut buf = [0; 512];

        // Test an EDNS-only message.
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer
            .add_answer_rr(*HINTED_NAME, Type::A, CLASS, *TTL, &RDATA, None)
            .unwrap();
        writer.set_edns(512).unwrap();
        writer.clear_rrs();
        assert_eq!(writer.arcount, 1);

        // Test a TSIG-only message.
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer
            .add_answer_rr(*HINTED_NAME, Type::A, CLASS, *TTL, &RDATA, None)
            .unwrap();
        writer.set_tsig(TSIG_MODE.clone(), TSIG_RR.clone()).unwrap();
        writer.clear_rrs();
        assert_eq!(writer.arcount, 1);

        // Test an EDNS + TSIG message.
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer
            .add_answer_rr(*HINTED_NAME, Type::A, CLASS, *TTL, &RDATA, None)
            .unwrap();
        writer.set_edns(512).unwrap();
        writer.set_tsig(TSIG_MODE.clone(), TSIG_RR.clone()).unwrap();
        writer.clear_rrs();
        assert_eq!(writer.arcount, 2);
    }

    #[test]
    fn hint_pointer_constructor_accepts_valid_values() {
        for pointer in 1..=POINTER_MAX {
            assert!(HintPointer::new(pointer).is_some());
        }
    }

    #[test]
    fn hint_pointer_constructor_rejects_invalid_values() {
        assert!(HintPointer::new(0).is_none());
        assert!(HintPointer::new(POINTER_MAX + 1).is_none());
    }
}
