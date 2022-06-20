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

//! The processing logic of an authoritative DNS server.
//!
//! The [`Server`] structure is the heart of this module; see its
//! documentation for details.

use std::net::IpAddr;

use crate::message::reader::ReadRr;
use crate::message::{writer, ExtendedRcode, Opcode, Question, Rcode, Reader, Writer};
use crate::name::Name;
use crate::rr::Type;
use crate::zone::Catalog;

mod query;
mod rrl;

use rrl::Rrl;
pub use rrl::{RrlParamError, RrlParams};

////////////////////////////////////////////////////////////////////////
// SERVER PUBLIC API AND CORE MESSAGE-HANDLING LOGIC                  //
////////////////////////////////////////////////////////////////////////

/// An authoritative DNS server, abstracted from any underlying network
/// I/O provider.
///
/// The [`Server`] structure implements the message-processing logic of
/// an authoritative DNS server. It receives, parses, and responds to
/// DNS messages through the [`Server::handle_message`] method. An
/// underlying network I/O provider is responsible for receiving these
/// messages from the network through whatever operating system I/O APIs
/// are chosen, and then sending the responses that the [`Server`]
/// produces.
///
/// The [`Server`] in turn produces responses based on its [`Catalog`]
/// of [`Zone`](crate::zone::Zone)s loaded into memory. A [`Server`] is
/// created to serve a [`Catalog`] with [`Server::new`].
pub struct Server {
    catalog: Catalog,
    rrl: Option<Rrl>,
}

impl Server {
    /// Creates a new `Server` that will serve the provided [`Catalog`].
    pub fn new(catalog: Catalog) -> Self {
        Self { catalog, rrl: None }
    }

    /// Configures response rate-limiting for this `Server`. If passed
    /// `None`, then rate-limiting is disabled.
    pub fn set_rrl_params(&mut self, rrl_params: Option<RrlParams>) {
        self.rrl = rrl_params.map(Rrl::new);
    }

    /// Handles a received DNS message. This is the API through which
    /// I/O providers submit messages.
    ///
    /// `received_buf` contains the message received, and `received_info`
    /// provides additional information about it (see [`ReceivedInfo`]).
    /// `response_buf` is a buffer into which a response message may be
    /// serialized. Its length is interpreted as the maximum size of a
    /// DNS message the caller is willing to send. To comply with the
    /// DNS specification, it should be at least 512 octets long for UDP
    /// transport. For TCP transport, the maximum possible size (65,535
    /// octets) should be used. If the buffer is not long enough to hold
    /// a DNS message header, then this method will panic.
    ///
    /// A [`Response`] is returned, signifying whether a response is to
    /// be sent and, if so, how long the response message written into
    /// `response_buf` is.
    pub fn handle_message(
        &self,
        received_buf: &[u8],
        received_info: ReceivedInfo,
        response_buf: &mut [u8],
    ) -> Response {
        // Construct a Reader, while ignoring messages that do not
        // contain a full DNS header.
        let received = match Reader::try_from(received_buf) {
            Ok(r) => r,
            Err(_) => return Response::None,
        };

        // Ignore messages that are responses.
        if received.qr() {
            return Response::None;
        }

        // Start the response by copying information from the received
        // message and setting the QR bit.
        let response_size_limit = match received_info.transport {
            Transport::Tcp => u16::MAX as usize,
            Transport::Udp => 512,
        };
        let mut response = Writer::new(response_buf, response_size_limit)
            .expect("failed to start response (buffer too short)");
        response.set_id(received.id());
        response.set_qr(true);
        response.set_opcode(received.opcode());
        if received.opcode() == Opcode::QUERY {
            // Per the ISC DNS compliance testing tool, RD is only
            // defined for opcode QUERY and thus we shouldn't copy it
            // otherwise.
            response.set_rd(received.rd());
        }

        // We now have our Reader and Writer set up. Next, we create a
        // Context structure, which holds the Reader/Writer and also
        // keeps track of other information recorded during the
        // message-handling process. The handle_message_with_context
        // method then finishes processing and response creation.
        let mut context = Context::new(received, received_info, response);
        self.handle_message_with_context(&mut context);

        // The final step is to apply response rate-limiting (RRL) if
        // it's enabled.
        if let Some(ref rrl) = self.rrl {
            rrl.process_response(&mut context);
        }

        // Send away (if we should)!
        if context.send_response {
            Response::Single(context.response.finish())
        } else {
            Response::None
        }
    }

    /// Handles a received DNS message once a [`Context`] has been
    /// constructed. This is a continuation of
    /// [`Server::handle_message`] that performs additional generic
    /// processing (such as looking for OPT records) before calling into
    /// opcode-specific processing. At the conclusion of this method,
    /// the response (if any) has been prepared. Post-processing occurs
    /// once this returns to [`Server::handle_message`].
    fn handle_message_with_context<'s>(&'s self, context: &mut Context<'s, '_>) {
        // Read the question, if any. Note that most current
        // implementations ignore messages with QDCOUNT > 1, so we'll do
        // the same.
        //
        // If there is a question, add it to the response.
        context.question = match context.received.qdcount() {
            0 => None,
            1 => {
                if let Ok(question) = context.received.read_question() {
                    if context.response.add_question(&question).is_err() {
                        context.response.set_rcode(Rcode::SERVFAIL);
                        return;
                    }
                    Some(question)
                } else {
                    context.response.set_rcode(Rcode::FORMERR);
                    return;
                }
            }
            _ => {
                context.send_response = false;
                return;
            }
        };

        // DNS servers tend to be lax about allowing random records in
        // non-response messages, at least for opcode QUERY, and we
        // haven't come across anything in the RFCs to forbid it. In
        // fact, RFC 1996 *requires* servers to accept records in the
        // authority and additional sections of NOTIFY messages in case
        // future versions of NOTIFY make use of them. So our strategy
        // is to ignore the RRs that we're not yet concerned with and to
        // allow opcode-specific handling to deal with them (or, for
        // e.g. QUERY and NOTIFY, ignore them).
        //
        // We do, however, need to skip over them here to process
        // pseudo-RRs like OPT or TSIG. This raises the question: should
        // we attempt to parse/decompress them (and return FORMERR if
        // they are invalid)? This would be nice and fastidious, and
        // some servers seem to do it. Furthermore, we *may*, for
        // certain opcodes, need that data later. But on the other hand,
        // it would be good to avoid pedantically parsing a bunch of
        // superfluous RRs in a QUERY, for example. We don't want an
        // attacker slowing us down by feeding us tons of junk records,
        // or trying to blow up our memory usage by sending lots of
        // unused RRs with compressed domain names (especially if we're
        // running on a thread-per-TCP-connection I/O provider).
        //
        // So instead, we do the bare minimum necessary: parsing the
        // first "chunk" of each RR owner (up to the null label or a
        // pointer label) to find the RDLENGTH field, and then using the
        // RDLENGTH field to get to the end of the RR. Thus, if there
        // are superfluous RRs with invalid data, we let it slide. That
        // seems okay---after all, this is an authoritative server, not
        // a DNS message validation service!

        // We'll rewind to the beginning of the RRs after we scan them.
        context.received.mark();

        // Scan all the answer and authority RRs. RFC 6891 § 6.1.1 says
        // that the EDNS OPT record goes in additional section, so if we
        // see it in these two sections, return FORMERR.
        let an_plus_ns_count =
            context.received.ancount() as usize + context.received.nscount() as usize;
        for _ in 0..an_plus_ns_count {
            let peek_rr = match context.received.peek_rr() {
                Ok(p) => p,
                Err(_) => {
                    context.response.set_rcode(Rcode::FORMERR);
                    return;
                }
            };
            if peek_rr.rr_type() == Type::OPT {
                context.response.set_rcode(Rcode::FORMERR);
                return;
            } else {
                peek_rr.skip();
            }
        }

        // Scan the additional section. If we see an OPT, now's the time
        // to process it.
        let mut seen_opt = false;
        for _ in 0..context.received.arcount() as usize {
            let peek_rr = match context.received.peek_rr() {
                Ok(p) => p,
                Err(_) => {
                    context.response.set_rcode(Rcode::FORMERR);
                    return;
                }
            };
            if peek_rr.rr_type() == Type::OPT {
                // Per RFC 6891 § 6.1.1, we must return FORMERR if more
                // than one OPT is received.
                if seen_opt {
                    context.response.set_rcode(Rcode::FORMERR);
                    return;
                } else {
                    seen_opt = true;
                }

                // Once we find an OPT record, we produce an EDNS
                // response, even if the OPT record is invalid (see
                // RFC 6891 § 7).
                if context.response.set_edns(512).is_err() {
                    context.response.set_rcode(Rcode::SERVFAIL);
                    return;
                }
                let opt_rr = match peek_rr.parse() {
                    Ok(opt_rr) => opt_rr,
                    Err(_) => {
                        context.response.set_rcode(Rcode::FORMERR);
                        return;
                    }
                };
                if let Some(rcode) = validate_opt(&opt_rr) {
                    context
                        .response
                        .set_extended_rcode(rcode)
                        .expect("failed to set extended RCODE");
                    return;
                }
            }
        }

        // At this point, we ought to be at the end of the message.
        if !context.received.at_eom() {
            context.response.set_rcode(Rcode::FORMERR);
        }
        context.received.rewind();

        // With preliminary checks complete, it's time to start the
        // opcode-specific handling!
        match context.received.opcode() {
            Opcode::QUERY => self.handle_query(context),
            _ => context.response.set_rcode(Rcode::NOTIMP),
        }
    }
}

/// Provides network-related information about a received DNS message to
/// [`Server::handle_message`].
#[derive(Clone, Copy, Debug)]
pub struct ReceivedInfo {
    pub source: IpAddr,
    pub transport: Transport,
}

/// Indicates the transport through which a DNS message was received.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Indicates to the caller of [`Server::handle_message`] what kind of
/// response needs to be sent.
pub enum Response {
    /// A single response is to be sent. The response has been written
    /// into the provided buffer. The length of the response is
    /// included.
    Single(usize),

    /// No response is to be sent.
    None,
}

////////////////////////////////////////////////////////////////////////
// MESSAGE-HANDLING CONTEXT                                           //
////////////////////////////////////////////////////////////////////////

/// Contains data involved in DNS message-handling. This includes the
/// received message and the response under construction, as well as
/// other data set or consumed at different stages of the process.
struct Context<'s, 'b> {
    // Information on the received message:
    received: Reader<'b>,
    received_info: ReceivedInfo,
    question: Option<Question>,

    // Data recorded during processing:
    source_of_synthesis: Option<&'s Name>,

    // Information on the response:
    response: Writer<'b>,
    rrl_action: Option<rrl::Action>,
    send_response: bool,
}

impl<'s, 'b> Context<'s, 'b> {
    /// Creates a new `Context`.
    fn new(received: Reader<'b>, received_info: ReceivedInfo, response: Writer<'b>) -> Self {
        Self {
            received,
            received_info,
            question: None,
            source_of_synthesis: None,
            response,
            rrl_action: None,
            send_response: true,
        }
    }
}

////////////////////////////////////////////////////////////////////////
// EDNS OPT RECORD HANDLING                                           //
////////////////////////////////////////////////////////////////////////

/// Validates an EDNS OPT record. If it's not valid, then the proper
/// error RCODE for the response is returned.
fn validate_opt(opt_rr: &ReadRr) -> Option<ExtendedRcode> {
    // The formatting of the OPT RDATA was already validated when we
    // parsed it, and since we currently don't support any EDNS options,
    // we ignore any sent to us (per RFC 6891 § 6.1.2). What remains is
    // to check the owner name and the EDNS version.
    if !opt_rr.owner.is_root() {
        Some(ExtendedRcode::FORMERR)
    } else {
        let edns_version = (u32::from(opt_rr.ttl) >> 16) as u8;
        if edns_version != 0 {
            Some(ExtendedRcode::BADVERSBADSIG)
        } else {
            None
        }
    }
}

////////////////////////////////////////////////////////////////////////
// PROCESSING ERRORS                                                  //
////////////////////////////////////////////////////////////////////////

/// An error internal to the [`server`](crate::server) module used to
/// signal problems encountered while processing a DNS message.
#[derive(Debug, Eq, PartialEq)]
enum ProcessingError {
    ServFail,
    Truncation,
}

impl From<writer::Error> for ProcessingError {
    fn from(writer_error: writer::Error) -> Self {
        match writer_error {
            writer::Error::Truncation => Self::Truncation,
            _ => Self::ServFail,
        }
    }
}

/// A result type used internally by [`server`](crate::server) functions
/// that process DNS messages.
type ProcessingResult<T> = Result<T, ProcessingError>;
