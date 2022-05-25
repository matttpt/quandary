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

use super::constants::*;
use super::{Opcode, Question, Rcode};
use crate::class::Class;
use crate::name::Name;
use crate::rr::{Rdata, Rrset, Ttl, Type};

////////////////////////////////////////////////////////////////////////
// WRITER                                                             //
////////////////////////////////////////////////////////////////////////

/// A "frame" around a buffer that serializes a DNS message into it.
///
/// A `Writer` is constructed using its [`TryFrom`] implementation. Any
/// underlying buffer for a `Writer` must have space for at least a
/// full DNS message header of 12 octets; otherwise the construction
/// will fail. The message header is initially zeroed.
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
pub struct Writer<'a> {
    octets: &'a mut [u8],
    cursor: usize,
    rr_start: usize,
    section: Section,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
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

impl Writer<'_> {
    /// Sets the 16-bit ID of the message.
    pub fn set_id(&mut self, id: u16) {
        self.write_u16(ID_START, id);
    }

    /// Sets or clears the QR (query response) bit.
    pub fn set_qr(&mut self, qr: bool) {
        if qr {
            self.octets[QR_BYTE] |= QR_MASK;
        } else {
            self.octets[QR_BYTE] &= !QR_MASK;
        }
    }

    /// Sets the message's opcode.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.octets[OPCODE_BYTE] &= !OPCODE_MASK;
        self.octets[OPCODE_BYTE] |= u8::from(opcode) << OPCODE_SHIFT;
    }

    /// Sets or clears the AA (authoritative answer) bit.
    pub fn set_aa(&mut self, aa: bool) {
        if aa {
            self.octets[AA_BYTE] |= AA_MASK;
        } else {
            self.octets[AA_BYTE] &= !AA_MASK;
        }
    }

    /// Sets or clears the TC (truncation) bit.
    pub fn set_tc(&mut self, tc: bool) {
        if tc {
            self.octets[TC_BYTE] |= TC_MASK;
        } else {
            self.octets[TC_BYTE] &= !TC_MASK;
        }
    }

    /// Sets or clears the RD (recursion desired) bit.
    pub fn set_rd(&mut self, rd: bool) {
        if rd {
            self.octets[RD_BYTE] |= RD_MASK;
        } else {
            self.octets[RD_BYTE] &= !RD_MASK;
        }
    }

    /// Sets or clears the RA (recursion available) bit.
    pub fn set_ra(&mut self, ra: bool) {
        if ra {
            self.octets[RA_BYTE] |= RA_MASK;
        } else {
            self.octets[RA_BYTE] &= !RA_MASK;
        }
    }

    /// Sets the message's RCODE.
    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.octets[RCODE_BYTE] &= !RCODE_MASK;
        self.octets[RCODE_BYTE] |= u8::from(rcode);
    }

    /// Adds a question to message. This must be used before any
    /// resource records are added.
    pub fn add_question(&mut self, question: &Question) -> Result<()> {
        if self.section != Section::Question {
            Err(Error::OutOfOrder)
        } else if let Some(new_qdcount) = self.qdcount.checked_add(1) {
            self.with_rollback(|this| {
                this.try_push(question.qname.wire_repr())?;
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
    /// RRs are added to any other section.
    pub fn add_answer_rr(
        &mut self,
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_answer()?;
            this.add_rr(owner, rr_type, class, ttl, rdata)?;
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
    /// any other section.
    pub fn add_answer_rrset(&mut self, owner: &Name, rrset: &Rrset) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_answer()?;
            let n_added = this.add_rrset(owner, rrset)?;
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
    /// and before any additional RRs are added.
    pub fn add_authority_rr(
        &mut self,
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_authority()?;
            this.add_rr(owner, rr_type, class, ttl, rdata)?;
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
    /// before any additional RRs are added.
    pub fn add_authority_rrset(&mut self, owner: &Name, rrset: &Rrset) -> Result<()> {
        self.with_rollback(|this| {
            this.change_section_to_authority()?;
            let n_added = this.add_rrset(owner, rrset)?;
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
    /// sections are added.
    pub fn add_additional_rr(
        &mut self,
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<()> {
        self.with_rollback(|this| {
            this.section = Section::Additional;
            this.add_rr(owner, rr_type, class, ttl, rdata)?;
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
    /// are added.
    pub fn add_additional_rrset(&mut self, owner: &Name, rrset: &Rrset) -> Result<()> {
        self.with_rollback(|this| {
            this.section = Section::Additional;
            let n_added = this.add_rrset(owner, rrset)?;
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
        owner: &Name,
        rr_type: Type,
        class: Class,
        ttl: Ttl,
        rdata: &Rdata,
    ) -> Result<()> {
        self.try_push(owner.wire_repr())?;
        self.try_push_u16(rr_type.into())?;
        self.try_push_u16(class.into())?;
        self.try_push_u32(ttl.into())?;
        self.try_push_u16(rdata.len() as u16)?;
        self.try_push(rdata.octets())
    }

    /// Writes out an RRset at the current cursor. This is for internal
    /// use: the write is not done atomically and may change the cursor
    /// even when an error is returned. This is intended to be used with
    /// [`Writer::with_rollback`].
    fn add_rrset(&mut self, owner: &Name, rrset: &Rrset) -> Result<usize> {
        let mut n_added = 0;
        for rdata in rrset.rdatas() {
            self.add_rr(owner, rrset.rr_type, rrset.class, rrset.ttl, rdata)?;
            n_added += 1;
        }
        Ok(n_added)
    }

    /// Removes any resource records previously added to the message.
    pub fn clear_rrs(&mut self) {
        self.ancount = 0;
        self.nscount = 0;
        self.arcount = 0;
        self.cursor = self.rr_start;
        self.section = Section::Question;
    }

    /// Finishes writing the message. The final length of the message
    /// is returned.
    pub fn finish(mut self) -> usize {
        self.write_u16(QDCOUNT_START, self.qdcount);
        self.write_u16(ANCOUNT_START, self.ancount);
        self.write_u16(NSCOUNT_START, self.nscount);
        self.write_u16(ARCOUNT_START, self.arcount);
        self.cursor
    }

    /// Executes `f(self)`, returning the result and rolling back the
    /// section and cursor to the current values first if the result is
    /// an error.
    fn with_rollback<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let saved_section = self.section;
        let saved_cursor = self.cursor;
        let result = f(self);
        if result.is_err() {
            self.section = saved_section;
            self.cursor = saved_cursor;
        }
        result
    }

    /// Tries to write `data` to the underlying buffer at the current
    /// cursor, failing if there is not sufficient space.
    fn try_push(&mut self, data: &[u8]) -> Result<()> {
        if self.octets.len() - self.cursor >= data.len() {
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
        if octets.len() < HEADER_SIZE {
            Err(Error::Truncation)
        } else {
            octets[0..HEADER_SIZE].fill(0);
            Ok(Self {
                octets,
                cursor: HEADER_SIZE,
                rr_start: HEADER_SIZE,
                section: Section::Question,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            })
        }
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::CountOverflow => f.write_str("record count would overflow"),
            Self::Truncation => f.write_str("message would be truncated"),
            Self::OutOfOrder => f.write_str("question or record serialized out of order"),
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
    use lazy_static::lazy_static;

    use super::super::Question;
    use super::*;

    lazy_static! {
        static ref NAME: Box<Name> = "quandary.test.".parse().unwrap();
        static ref QUESTION: Question = Question {
            qname: NAME.clone(),
            qtype: Type::A.into(),
            qclass: Class::IN.into(),
        };
        static ref RDATA: &'static Rdata = b"\x7f\x00\x00\x01".try_into().unwrap();
        static ref RRSET: Rrset = {
            let mut rrset = Rrset::new(Type::A, Class::IN, Ttl::from(3600));
            rrset.push_rdata(*RDATA);
            rrset
        };
    }

    #[test]
    fn writer_works() {
        // This is not meant to be exhaustive by any means. Rather, it's
        // just a check that the Writer works in a basic scenario.
        let mut buf = vec![0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();
        writer.set_id(0x0703);
        writer.set_opcode(Opcode::Query);
        writer.set_qr(true);
        writer.set_aa(true);
        writer.set_rcode(Rcode::NoError);
        writer.add_question(&QUESTION).unwrap();
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();
        let len = writer.finish();
        assert_eq!(
            &buf[0..len],
            b"\x07\x03\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00\
              \x08quandary\x04test\x00\x00\x01\x00\x01\
              \x08quandary\x04test\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\
              \x7f\x00\x00\x01"
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
        add_rr: fn(&mut Writer<'a>, &Name, Type, Class, Ttl, &Rdata) -> Result<()>,
        add_rrset: fn(&mut Writer<'a>, &Name, &Rrset) -> Result<()>,
    ) {
        let mut writer = Writer::try_from(buf).unwrap();
        for _ in 0..u16::MAX {
            add_rrset(&mut writer, &NAME, &RRSET).unwrap();
        }
        assert_eq!(
            add_rr(
                &mut writer,
                &NAME,
                Type::A,
                Class::IN,
                Ttl::from(3600),
                *RDATA
            ),
            Err(Error::CountOverflow)
        );
        assert_eq!(
            add_rrset(&mut writer, &NAME, &RRSET),
            Err(Error::CountOverflow)
        );
    }

    #[test]
    fn writer_enforces_question_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Question.
        writer.add_question(&QUESTION).unwrap();

        // Check Question -> Question.
        writer.add_question(&QUESTION).unwrap();

        // Check Answer -> Question.
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));

        // Check Authority -> Question.
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));

        // Check Additional -> Question.
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(writer.add_question(&QUESTION), Err(Error::OutOfOrder));
    }

    #[test]
    fn writer_enforces_answer_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Answer.
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();

        // Check Answer -> Answer.
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();

        // Check Question -> Answer.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();

        // Check Authority -> Answer.
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(
            writer.add_answer_rrset(&NAME, &RRSET),
            Err(Error::OutOfOrder)
        );

        // Check Additional -> Answer.
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(
            writer.add_answer_rrset(&NAME, &RRSET),
            Err(Error::OutOfOrder)
        );
    }

    #[test]
    fn writer_enforces_authority_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Authority.
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();

        // Check Authority -> Authority.
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();

        // Check Question -> Authority.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();

        // Check Answer -> Authority.
        writer.clear_rrs();
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();

        // Check Additional -> Authority.
        writer.clear_rrs();
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();
        assert_eq!(
            writer.add_authority_rrset(&NAME, &RRSET),
            Err(Error::OutOfOrder)
        );
    }

    #[test]
    fn writer_enforces_additional_ordering() {
        let mut buf = [0; 512];
        let mut writer = Writer::try_from(buf.as_mut_slice()).unwrap();

        // Check empty (Question) -> Additional.
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();

        // Check Additional -> Additional.
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();

        // Check Question -> Additional.
        writer.clear_rrs();
        writer.add_question(&QUESTION).unwrap();
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();

        // Check Answer -> Additional.
        writer.clear_rrs();
        writer.add_answer_rrset(&NAME, &RRSET).unwrap();
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();

        // Check Authority -> Additional.
        writer.clear_rrs();
        writer.add_authority_rrset(&NAME, &RRSET).unwrap();
        writer.add_additional_rrset(&NAME, &RRSET).unwrap();
    }

    #[test]
    fn writer_constructor_rejects_short_buffer() {
        for size in 0..HEADER_SIZE {
            let mut buf = vec![0; size];
            assert!(matches!(
                Writer::try_from(buf.as_mut_slice()),
                Err(Error::Truncation)
            ));
        }
    }
}
