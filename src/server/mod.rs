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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

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
    catalog: RwLock<Arc<Catalog>>,
    edns_udp_payload_size: u16,
    rrl: Option<Rrl>,
}

impl Server {
    /// Creates a new `Server` that will serve the provided [`Catalog`].
    ///
    /// The default EDNS UDP payload size used is 1,232 octets. This is
    /// the safe default recommended for DNS Flag Day 2020, since 1,232
    /// (DNS message) + 8 (UDP header) + 40 (IPv6 header) = 1,280, the
    /// minimum MTU for IPv6. It should therefore avoid IP packet
    /// fragmentation on almost all present-day networks.
    ///
    /// By default, RRL is disabled. However, public servers should
    /// consider enabling it.
    pub fn new(catalog: Arc<Catalog>) -> Self {
        Self {
            catalog: RwLock::new(catalog),
            edns_udp_payload_size: 1232,
            rrl: None,
        }
    }

    /// Returns the current [`Catalog`] of the server.
    pub fn catalog(&self) -> Arc<Catalog> {
        self.catalog.read().unwrap().clone()
    }

    /// Sets the [`Catalog`] of the `Server`. Some in-flight message
    /// handling may continue to use the old [`Catalog`] (depending on
    /// how far it has gotten), but handling started after this call
    /// completes will see the new one.
    pub fn set_catalog(&self, catalog: Arc<Catalog>) {
        *self.catalog.write().unwrap() = catalog;
    }

    /// Returns the maximum UDP payload size that this `Server` will use
    /// with EDNS messages.
    pub fn edns_udp_payload_size(&self) -> u16 {
        self.edns_udp_payload_size
    }

    /// Sets the maximum UDP payload size that this `Server` will use
    /// with EDNS messages. This must be at least 512 octets (the
    /// maximum UDP payload size in unextended DNS).
    pub fn set_edns_udp_payload_size(&mut self, size: u16) -> Result<(), InvalidPayloadSizeError> {
        if size >= 512 {
            self.edns_udp_payload_size = size;
            Ok(())
        } else {
            Err(InvalidPayloadSizeError)
        }
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
    /// serialized. The caller must take care that these buffers are
    /// large enough. For UDP transport, the caller must be able to send
    /// and receive messages as large as the maximum configured size
    /// (use [`Server::edns_udp_payload_size`] to determine what this
    /// is). For TCP transport, the caller must be able to send and
    /// receive messages as large as 65,535 octets. In particular, if
    /// `response_buf` is not large enough to meet these requirements,
    /// then this method will panic.
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
        // Enforce our requirements on the size of response_buf.
        let min_response_buf_size = match received_info.transport {
            Transport::Tcp => u16::MAX as usize,
            Transport::Udp => self.edns_udp_payload_size as usize,
        };
        if response_buf.len() < min_response_buf_size {
            panic!("the response buffer is not large enough");
        }

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
        let mut response = Writer::new(response_buf, response_size_limit).unwrap();
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
        // Context structure, which holds a snapshot of the catalog,
        // stores the Reader/Writer, and also keeps track of other
        // information recorded during the message-handling process. The
        // handle_message_with_context method then finishes processing
        // and response creation.
        let catalog = self.catalog();
        let mut context = Context::new(&catalog, received, received_info, response);
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
                if context
                    .response
                    .set_edns(self.edns_udp_payload_size)
                    .is_err()
                {
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

                // For UDP transport, increase the message size limit if
                // possible. Note that Response::increase_limit never
                // *decreases* the limit, so we comply with
                // RFC 6891 § 6.2.5's requirement to treat payload sizes
                // less than 512 octets as equal to 512 octets.
                if context.received_info.transport == Transport::Udp {
                    let their_limit = u16::from(opt_rr.class);
                    let negotiated_limit = their_limit.min(self.edns_udp_payload_size);
                    context.response.increase_limit(negotiated_limit as usize);
                }

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
    source: IpAddr,
    transport: Transport,
}

impl ReceivedInfo {
    /// Creates a new [`ReceivedInfo`].
    ///
    /// It is important (particularly for RRL and IP-based ACLs) that
    /// IPv4-mapped IPv6 addresses of the kind that dual-stack sockets
    /// produce (e.g. `::ffff:127.0.0.1`) be interpreted as IPv4
    /// addresses. This function performs that canonicalization; calling
    /// I/O code need not concern itself with this task.
    pub fn new(source: IpAddr, transport: Transport) -> Self {
        // TODO: just use IpAddr::to_canonical if/when it's stabilized.
        let source = match source {
            original @ IpAddr::V4(_) => original,
            original @ IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                if octets[0..10].iter().all(|o| *o == 0) && octets[10] == 0xff && octets[11] == 0xff
                {
                    // This is an IPv4-mapped address.
                    IpAddr::V4(Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    ))
                } else {
                    original
                }
            }
        };
        Self { source, transport }
    }
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
struct Context<'c, 'b> {
    // Snapshot of the catalog at the beginning of processing:
    catalog: &'c Catalog,

    // Information on the received message:
    received: Reader<'b>,
    received_info: ReceivedInfo,
    question: Option<Question>,

    // Data recorded during processing:
    source_of_synthesis: Option<&'c Name>,

    // Information on the response:
    response: Writer<'b>,
    rrl_action: Option<rrl::Action>,
    send_response: bool,
}

impl<'c, 'b> Context<'c, 'b> {
    /// Creates a new `Context`.
    fn new(
        catalog: &'c Catalog,
        received: Reader<'b>,
        received_info: ReceivedInfo,
        response: Writer<'b>,
    ) -> Self {
        Self {
            catalog,
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
// PUBLIC ERRORS                                                      //
////////////////////////////////////////////////////////////////////////

/// An error returned when an invalid EDNS UDP payload size is passed
/// to [`Server::set_edns_udp_payload_size`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct InvalidPayloadSizeError;

impl fmt::Display for InvalidPayloadSizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid EDNS UDP payload size (the minimum is 512 octets)")
    }
}

impl std::error::Error for InvalidPayloadSizeError {}

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

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_edns_udp_payload_size_enforces_min() {
        let mut server = Server::new(Arc::new(Catalog::new()));
        assert!(server.set_edns_udp_payload_size(256).is_err());
    }

    #[test]
    #[should_panic(expected = "the response buffer is not large enough")]
    fn handle_message_rejects_short_buffers_for_tcp() {
        let server = Server::new(Arc::new(Catalog::new()));
        let received_info = ReceivedInfo::new(Ipv4Addr::LOCALHOST.into(), Transport::Tcp);
        let mut not_quite_large_enough = [0; u16::MAX as usize - 1];
        server.handle_message(&[], received_info, &mut not_quite_large_enough);
    }

    #[test]
    #[should_panic(expected = "the response buffer is not large enough")]
    fn handle_message_rejects_short_buffers_for_udp() {
        let server = Server::new(Arc::new(Catalog::new()));
        let received_info = ReceivedInfo::new(Ipv4Addr::LOCALHOST.into(), Transport::Udp);
        let mut not_quite_large_enough = vec![0; server.edns_udp_payload_size() as usize - 1];
        server.handle_message(&[], received_info, &mut not_quite_large_enough);
    }

    #[test]
    fn received_info_constructor_canonicalizes_ipv4_mapped_ipv6_addrs() {
        let ipv4_mapped_ipv6 = "::ffff:127.0.0.1".parse().unwrap();
        let received_info = ReceivedInfo::new(ipv4_mapped_ipv6, Transport::Udp);
        assert_eq!(
            received_info.source,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
    }
}
