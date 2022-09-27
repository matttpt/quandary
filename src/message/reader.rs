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

//! Implementation of the [`Reader`] type to read on-the-wire DNS
//! messages.

use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::fmt;

use super::constants::*;
use super::{Opcode, Question, Rcode};
use crate::class::Class;
use crate::name::{self, Name};
use crate::rr::rdata::{Rdata, ReadRdataError};
use crate::rr::{Ttl, Type};

////////////////////////////////////////////////////////////////////////
// READER                                                             //
////////////////////////////////////////////////////////////////////////

/// A "frame" around a buffer containing a DNS message that enables
/// reading the message data.
///
/// A `Reader` is constructed using its [`TryFrom`] implementation. Any
/// underlying buffer for a reader must contain at least a full DNS
/// message header of 12 octets; otherwise the construction will fail.
///
/// Since header information is in a fixed position, it can be read
/// at any time through the appropriate `Reader` methods. For reading
/// questions and RRs, the [`Reader::read_question`] and
/// [`Reader::read_rr`] methods are provided. These read using a cursor,
/// which is initially set to the first octet after the DNS header. They
/// must be called sequentially to read any questions, and then any
/// records, in the order they appear in the message.
#[derive(Eq, PartialEq)]
pub struct Reader<'a> {
    octets: &'a [u8],
    cursor: usize,
    mark: Option<usize>,
}

impl<'a> Reader<'a> {
    /// Returns the 16-bit ID of the message.
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.octets[ID_START..ID_END].try_into().unwrap())
    }

    /// Returns whether the QR (query response) bit is set.
    pub fn qr(&self) -> bool {
        (self.octets[QR_BYTE] & QR_MASK) != 0
    }

    /// Returns the message's opcode.
    pub fn opcode(&self) -> Opcode {
        let raw = (self.octets[OPCODE_BYTE] & OPCODE_MASK) >> OPCODE_SHIFT;
        raw.try_into().unwrap()
    }

    /// Returns whether the AA (authoritative answer) bit is set.
    pub fn aa(&self) -> bool {
        (self.octets[AA_BYTE] & AA_MASK) != 0
    }

    /// Returns whether the TC (truncation) bit is set.
    pub fn tc(&self) -> bool {
        (self.octets[TC_BYTE] & TC_MASK) != 0
    }

    /// Returns whether the RD (recursion desired) bit is set.
    pub fn rd(&self) -> bool {
        (self.octets[RD_BYTE] & RD_MASK) != 0
    }

    /// Returns whether the RA (recursion available) bit is set.
    pub fn ra(&self) -> bool {
        (self.octets[RA_BYTE] & RA_MASK) != 0
    }

    /// Returns the RCODE of the message.
    pub fn rcode(&self) -> Rcode {
        let raw = self.octets[RCODE_BYTE] & RCODE_MASK;
        raw.try_into().unwrap()
    }

    /// Returns the number of questions in the message.
    pub fn qdcount(&self) -> u16 {
        u16::from_be_bytes(self.octets[QDCOUNT_START..QDCOUNT_END].try_into().unwrap())
    }

    /// Returns the number of answers in the message.
    pub fn ancount(&self) -> u16 {
        u16::from_be_bytes(self.octets[ANCOUNT_START..ANCOUNT_END].try_into().unwrap())
    }

    /// Returns the number of authority records in the message.
    pub fn nscount(&self) -> u16 {
        u16::from_be_bytes(self.octets[NSCOUNT_START..NSCOUNT_END].try_into().unwrap())
    }

    /// Returns the number of additional records in the message.
    pub fn arcount(&self) -> u16 {
        u16::from_be_bytes(self.octets[ARCOUNT_START..ARCOUNT_END].try_into().unwrap())
    }

    /// Marks the current position in the message for a later call to
    /// [`Reader::rewind`].
    pub fn mark(&mut self) {
        self.mark = Some(self.cursor);
    }

    /// Rewinds the `Reader` back to the position where [`Reader::mark`]
    /// was previously called and clears the mark. If [`Reader::mark`]
    /// was never called, or if the previous mark was already cleared by
    /// a call to this method, then this will panic.
    pub fn rewind(&mut self) {
        self.cursor = self.mark.expect("Reader rewound with no mark set");
        self.mark = None;
    }

    /// Reads a [`Question`] starting at the current cursor.
    ///
    /// This method is atomic, in that the cursor is not changed on
    /// failure.
    pub fn read_question(&mut self) -> Result<Question> {
        let (qname, qname_len) =
            Name::try_from_compressed(self.octets, self.cursor).map_err(Error::InvalidQname)?;
        let qname_end = self.cursor + qname_len;
        let qtype = read_u16(&self.octets[qname_end..])?.into();
        let qclass = read_u16(&self.octets[qname_end + 2..])?.into();
        self.cursor += qname_len + 4;
        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    /// Skips a question at the current cursor.
    ///
    /// Note that the QNAME is not fully validated. If it is compressed,
    /// then it is checked only until the first pointer label.
    ///
    /// This method is atomic, in that the cursor is not changed on
    /// failure.
    pub fn skip_question(&mut self) -> Result<()> {
        let qname_len =
            Name::skip_compressed(&self.octets[self.cursor..]).map_err(Error::InvalidQname)?;
        let qname_end = self.cursor + qname_len;
        let question_end = qname_end + 4;
        if question_end > self.octets.len() {
            Err(Error::UnexpectedEomInField)
        } else {
            self.cursor = question_end;
            Ok(())
        }
    }

    /// Reads a resource record at the current cursor.
    ///
    /// This method is atomic, in that the cursor is not changed on
    /// failure.
    pub fn read_rr(&mut self) -> Result<ReadRr<'a>> {
        let (owner, owner_len) =
            Name::try_from_compressed(self.octets, self.cursor).map_err(Error::InvalidOwner)?;
        let owner_end = self.cursor + owner_len;
        let rr_type = read_u16(&self.octets[owner_end..])?.into();
        let class = read_u16(&self.octets[owner_end + 2..])?.into();
        let ttl = read_u32(&self.octets[owner_end + 4..])?.into();
        let rdlength = read_u16(&self.octets[owner_end + 8..])?;
        let rdata = Rdata::read(rr_type, self.octets, self.cursor + owner_len + 10, rdlength)?;
        self.cursor = owner_end + 10 + rdlength as usize;
        Ok(ReadRr {
            owner,
            rr_type,
            class,
            ttl,
            rdata,
        })
    }

    /// Skips a resource record at the current cursor.
    ///
    /// Note that the resource record is not fully validated. If the
    /// owner name is compressed, it is checked only until the first
    /// pointer label. Furthermore, the RDATA length is checked, but the
    /// RDATA content itself is not validated.
    pub fn skip_rr(&mut self) -> Result<()> {
        let owner_len =
            Name::skip_compressed(&self.octets[self.cursor..]).map_err(Error::InvalidOwner)?;
        let owner_end = self.cursor + owner_len;
        let rdlength = read_u16(&self.octets[owner_end + 8..])?;
        let rr_end = owner_end + 10 + rdlength as usize;
        if rr_end > self.octets.len() {
            Err(Error::InvalidRdata(ReadRdataError::UnexpectedEom))
        } else {
            self.cursor = rr_end;
            Ok(())
        }
    }

    /// Peeks at a resource record at the current cursor.
    ///
    /// This returns a [`PeekRr`] structure that allows one to inspect
    /// certain fields of the RR without fully parsing/decompressing it.
    /// Note that the RR is not fully validated; this method performs
    /// the same checks as [`Reader::skip_rr`].
    pub fn peek_rr<'r>(&'r mut self) -> Result<PeekRr<'r, 'a>> {
        let owner_len =
            Name::skip_compressed(&self.octets[self.cursor..]).map_err(Error::InvalidOwner)?;
        let owner_end = self.cursor + owner_len;
        let rdlength = read_u16(&self.octets[owner_end + 8..])?;
        let rr_end = owner_end + 10 + rdlength as usize;
        if rr_end > self.octets.len() {
            Err(Error::InvalidRdata(ReadRdataError::UnexpectedEom))
        } else {
            Ok(PeekRr {
                reader: self,
                owner: None,
                owner_end,
                rr_end,
            })
        }
    }

    /// Returns whether the `Reader`'s cursor has reached the end of the
    /// message.
    pub fn at_eom(&self) -> bool {
        self.cursor >= self.octets.len()
    }

    /// Returns the message up to the current cursor.
    pub fn message_to_cursor(&self) -> &'a [u8] {
        &self.octets[0..self.cursor]
    }
}

impl<'a> TryFrom<&'a [u8]> for Reader<'a> {
    type Error = Error;

    fn try_from(octets: &'a [u8]) -> Result<Self> {
        if octets.len() >= HEADER_SIZE {
            Ok(Self {
                octets,
                cursor: HEADER_SIZE,
                mark: None,
            })
        } else {
            Err(Error::HeaderTooShort)
        }
    }
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Reader")
            .field("id", &self.id())
            .field("qr", &self.qr())
            .field("opcode", &self.opcode())
            .field("aa", &self.aa())
            .field("tc", &self.tc())
            .field("rd", &self.rd())
            .field("ra", &self.ra())
            .field("rcode", &self.rcode())
            .field("qdcount", &self.qdcount())
            .field("ancount", &self.ancount())
            .field("nscount", &self.nscount())
            .field("arcount", &self.arcount())
            .field("cursor", &self.cursor)
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////
// RECORD-PEEKING IMPLEMENTATION                                      //
////////////////////////////////////////////////////////////////////////

/// Gives a peek at a resource record's fields without completely
/// parsing/decompressing it.
///
/// Using [`Reader::peek_rr`] and this type, one can quickly scan for
/// RRs of interest before parsing/decompressing their owner domain
/// names and RDATA (and dynamically allocating space for them). The
/// fixed-size fields can be accessed through their respective methods,
/// and the owner domain name can be parsed on demand with
/// [`PeekRr::owner`].
///
/// After inspecting an RR, one may drop the [`PeekRr`], leaving the
/// parent [`Reader`]'s state unchanged; call [`PeekRr::skip`] to
/// advance the parent [`Reader`] to the end of the RR without parsing
/// it; or [`PeekRr::parse`] to fully parse the record's owner and
/// RDATA.
pub struct PeekRr<'r, 'b> {
    reader: &'r mut Reader<'b>,
    owner: Option<Box<Name>>,
    owner_end: usize,
    rr_end: usize,
}

impl<'r, 'b> PeekRr<'r, 'b> {
    /// Returns the owner of the resource record. It is parsed when this
    /// method is first called; subsequent calls return a reference to
    /// the same [`Name`].
    pub fn owner(&mut self) -> Result<&Name> {
        if let Some(ref owner) = self.owner {
            Ok(owner)
        } else {
            Ok(self.owner.insert(self.parse_owner()?))
        }
    }

    /// Parses the resource record's owner.
    fn parse_owner(&self) -> Result<Box<Name>> {
        Name::try_from_compressed(self.reader.octets, self.reader.cursor)
            .map(|(owner, _)| owner)
            .map_err(Error::InvalidOwner)
    }

    /// Removes and returns the name from the owner field if it has
    /// already been parsed; otherwise, parses the owner.
    fn take_owner(&mut self) -> Result<Box<Name>> {
        if let Some(owner) = self.owner.take() {
            Ok(owner)
        } else {
            self.parse_owner()
        }
    }

    /// Returns the resource record's type.
    pub fn rr_type(&self) -> Type {
        Type::from(u16::from_be_bytes(
            self.reader.octets[self.owner_end..self.owner_end + 2]
                .try_into()
                .unwrap(),
        ))
    }

    /// Returns the resource record's class.
    pub fn class(&self) -> Class {
        Class::from(u16::from_be_bytes(
            self.reader.octets[self.owner_end + 2..self.owner_end + 4]
                .try_into()
                .unwrap(),
        ))
    }

    /// Returns the resource record's time-to-live.
    pub fn ttl(&self) -> Ttl {
        Ttl::from(u32::from_be_bytes(
            self.reader.octets[self.owner_end + 4..self.owner_end + 8]
                .try_into()
                .unwrap(),
        ))
    }

    /// Returns the resource record's RDLENGTH field.
    pub fn rdlength(&self) -> u16 {
        u16::from_be_bytes(
            self.reader.octets[self.owner_end + 8..self.owner_end + 10]
                .try_into()
                .unwrap(),
        )
    }

    /// Returns the message up to, but not including, the current RR.
    pub fn message_to_rr(&self) -> &'b [u8] {
        self.reader.message_to_cursor()
    }

    /// Advances the parent [`Reader`] to the end of the resource record
    /// without parsing the record.
    pub fn skip(mut self) {
        self.reader.cursor = self.rr_end;
    }

    /// Parses the resource record and advances the parent [`Reader`] to
    /// its end.
    ///
    /// Like [`Reader::read_rr`], this method is atomic, in that the
    /// parent [`Reader`]'s cursor is not advanced on failure.
    pub fn parse(mut self) -> Result<ReadRr<'b>> {
        let owner = self.take_owner()?;
        let rdata = Rdata::read(
            self.rr_type(),
            self.reader.octets,
            self.owner_end + 10,
            self.rdlength(),
        )?;
        self.reader.cursor = self.rr_end;
        Ok(ReadRr {
            owner,
            rr_type: self.rr_type(),
            class: self.class(),
            ttl: self.ttl(),
            rdata,
        })
    }
}

////////////////////////////////////////////////////////////////////////
// HELPERS FOR READING MULTI-BYTE INTEGERS                            //
////////////////////////////////////////////////////////////////////////

/// Reads a network-byte-order `u16` from the beginning of `octets`.
fn read_u16(octets: &[u8]) -> Result<u16> {
    let array = octets
        .get(0..2)
        .ok_or(Error::UnexpectedEomInField)?
        .try_into()
        .unwrap();
    Ok(u16::from_be_bytes(array))
}

/// Reads a network-byte-order `u32` from the beginning of `octets`.
fn read_u32(octets: &[u8]) -> Result<u32> {
    let array = octets
        .get(0..4)
        .ok_or(Error::UnexpectedEomInField)?
        .try_into()
        .unwrap();
    Ok(u32::from_be_bytes(array))
}

////////////////////////////////////////////////////////////////////////
// READ RR STRUCTURE                                                  //
////////////////////////////////////////////////////////////////////////

/// A structure containing RR data as returned by [`Reader::read_rr`].
///
/// This is primarily for convenience (as opposed to returning a complex
/// tuple type). It is defined *here*, instead of the [`rr`](crate::rr)
/// module, because the RR handling code itself deals primarily with
/// RRsets. Also, by doing so, this type can have the exact right
/// combination of owned versus borrowed members for
/// [`Reader::read_rr`].
#[derive(Clone)]
pub struct ReadRr<'a> {
    pub owner: Box<Name>,
    pub rr_type: Type,
    pub class: Class,
    pub ttl: Ttl,
    pub rdata: Cow<'a, Rdata>,
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error signaling that a [`Question`] or resource record could not
/// be read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    HeaderTooShort,
    UnexpectedEomInField,
    InvalidQname(name::Error),
    InvalidOwner(name::Error),
    InvalidRdata(ReadRdataError),
}

impl From<ReadRdataError> for Error {
    fn from(err: ReadRdataError) -> Self {
        Self::InvalidRdata(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::HeaderTooShort => f.write_str("header too short"),
            Self::UnexpectedEomInField => f.write_str("unexpected end of message in field"),
            Self::InvalidQname(err) => write!(f, "invalid QNAME: {}", err),
            Self::InvalidOwner(err) => write!(f, "invalid owner: {}", err),
            Self::InvalidRdata(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// The type returned by fallible [`Reader`] methods.
pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::super::{Qclass, Qtype};
    use super::*;

    /// This is a reply to a query for example.com. IN NS to a recursive
    /// server, made on January 7, 2022.
    const EXAMPLE_COM_NS_MESSAGE: &[u8] =
        b"\xe2\xd7\x81\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x65\x78\x61\
          \x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x02\x00\x01\xc0\x0c\x00\
          \x02\x00\x01\x00\x01\x50\xa2\x00\x14\x01\x61\x0c\x69\x61\x6e\x61\
          \x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74\x00\xc0\x0c\x00\
          \x02\x00\x01\x00\x01\x50\xa2\x00\x04\x01\x62\xc0\x2b\x00\x00\x29\
          \x10\x00\x00\x00\x00\x00\x00\x00";

    lazy_static! {
        static ref EXAMPLE_COM: Box<Name> = "example.com.".parse().unwrap();
        static ref A_IANA_SERVERS_NET: Box<Name> = "a.iana-servers.net.".parse().unwrap();
        static ref B_IANA_SERVERS_NET: Box<Name> = "b.iana-servers.net.".parse().unwrap();
    }

    #[test]
    fn reader_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();

        // Check the header.
        assert_eq!(reader.id(), 0xe2d7);
        assert!(reader.qr());
        assert_eq!(reader.opcode(), Opcode::QUERY);
        assert!(!reader.aa());
        assert!(!reader.tc());
        assert!(reader.rd());
        assert!(reader.ra());
        assert_eq!(reader.rcode(), Rcode::NOERROR);
        assert_eq!(reader.qdcount(), 1);
        assert_eq!(reader.ancount(), 2);
        assert_eq!(reader.nscount(), 0);
        assert_eq!(reader.arcount(), 1);

        // Check the question.
        let question = reader.read_question().unwrap();
        assert_eq!(question.qname, *EXAMPLE_COM);
        assert_eq!(question.qtype, Qtype::from(Type::NS));
        assert_eq!(question.qclass, Qclass::from(Class::IN));

        // Check the answers.
        let answer_1 = reader.read_rr().unwrap();
        assert_eq!(answer_1.owner, *EXAMPLE_COM);
        assert_eq!(answer_1.rr_type, Type::NS);
        assert_eq!(answer_1.class, Class::IN);
        assert_eq!(answer_1.ttl, Ttl::from(86178));
        assert_eq!(answer_1.rdata.octets(), A_IANA_SERVERS_NET.wire_repr());
        let answer_2 = reader.read_rr().unwrap();
        assert_eq!(answer_2.owner, *EXAMPLE_COM);
        assert_eq!(answer_2.rr_type, Type::NS);
        assert_eq!(answer_2.class, Class::IN);
        assert_eq!(answer_2.ttl, Ttl::from(86178));
        assert_eq!(answer_2.rdata.octets(), B_IANA_SERVERS_NET.wire_repr());

        // Check the OPT record.
        let opt = reader.read_rr().unwrap();
        assert_eq!(opt.owner.as_ref(), Name::root());
        assert_eq!(opt.rr_type, Type::OPT);
        assert_eq!(opt.class, Class::from(4096));
        assert!(opt.rdata.is_empty());

        // And that should be it!
        assert!(reader.at_eom());
    }

    #[test]
    fn reader_constructor_rejects_short_message() {
        for size in 0..HEADER_SIZE {
            let buf = vec![0; size];
            assert_eq!(Reader::try_from(buf.as_slice()), Err(Error::HeaderTooShort));
        }
    }

    #[test]
    fn reader_mark_and_rewind_work() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.mark();
        let question_the_first_time = reader.read_question().unwrap();
        assert_eq!(reader.cursor, 29);
        reader.rewind();
        assert_eq!(reader.cursor, HEADER_SIZE);
        let question_the_second_time = reader.read_question().unwrap();
        assert_eq!(question_the_first_time, question_the_second_time);
    }

    #[test]
    fn reader_rewind_unsets_mark() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.mark();
        assert!(reader.mark.is_some());
        reader.rewind();
        assert!(reader.mark.is_none());
    }

    #[test]
    #[should_panic(expected = "Reader rewound with no mark set")]
    fn reader_rewind_panics_when_no_mark_is_set() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.rewind();
    }

    #[test]
    fn reader_skip_question_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.skip_question().unwrap();
        assert_eq!(reader.cursor, 29);
    }

    #[test]
    fn reader_skip_rr_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.skip_question().unwrap();
        reader.skip_rr().unwrap();
        assert_eq!(reader.cursor, 61);
    }

    #[test]
    fn peek_rr_owner_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.skip_question().unwrap();
        let mut peek_rr = reader.peek_rr().unwrap();
        assert_eq!(peek_rr.owner(), Ok(EXAMPLE_COM.as_ref()));
    }

    #[test]
    fn peek_rr_skip_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.skip_question().unwrap();
        let peek_rr = reader.peek_rr().unwrap();
        peek_rr.skip();
        assert_eq!(reader.cursor, 61);
    }

    #[test]
    fn peek_rr_parse_works() {
        let mut reader = Reader::try_from(EXAMPLE_COM_NS_MESSAGE).unwrap();
        reader.skip_question().unwrap();
        let peek_rr = reader.peek_rr().unwrap();
        let answer = peek_rr.parse().unwrap();
        assert_eq!(reader.cursor, 61);
        assert_eq!(answer.owner, *EXAMPLE_COM);
        assert_eq!(answer.rr_type, Type::NS);
        assert_eq!(answer.class, Class::IN);
        assert_eq!(answer.ttl, Ttl::from(86178));
        assert_eq!(answer.rdata.octets(), A_IANA_SERVERS_NET.wire_repr());
    }
}
