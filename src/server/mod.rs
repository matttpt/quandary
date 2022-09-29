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

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::db::Catalog;
use crate::message::reader::ReadRr;
use crate::message::tsig::{Algorithm, PreparedTsigRr, ReadTsigRr};
use crate::message::{tsig, writer, ExtendedRcode, Opcode, Question, Rcode, Reader, Writer};
use crate::name::{LowercaseName, Name};
use crate::rr::rdata::TimeSigned;
use crate::rr::Type;

mod query;
mod rrl;

use rrl::Rrl;
pub use rrl::{RrlParamError, RrlParams};

////////////////////////////////////////////////////////////////////////
// SERVER PUBLIC API AND CORE MESSAGE-HANDLING LOGIC                  //
////////////////////////////////////////////////////////////////////////

/// An authoritative DNS server, abstracted from any underlying network
/// I/O provider or record database.
///
/// The [`Server`] structure implements the message-processing logic of
/// an authoritative DNS server. It receives, parses, and responds to
/// DNS messages through the [`Server::handle_message`] method. An
/// underlying network I/O provider is responsible for receiving these
/// messages from the network through whatever operating system I/O APIs
/// are chosen, and then sending the responses that the [`Server`]
/// produces.
///
/// The [`Server`] in turn produces responses based on its catalog of
/// zones. The [`Server`] type is generic over the catalog data
/// source chosen; see [`Catalog`] and [`Zone`](`crate::db::Zone`).
pub struct Server<C> {
    catalog: RwLock<Arc<C>>,
    edns_udp_payload_size: u16,
    rrl: Option<Rrl>,
    tsig_keys: RwLock<Arc<TsigKeyMap>>,
}

/// A [`HashMap`] giving a [`Server`]'s TSIG keys and their algorithms
/// by name.
///
/// While [RFC 8945] does not seem to prevent a single TSIG key from
/// being used with multiple algorithms, practically speaking, the key
/// length should be based on the algorithm in use. Therefore, we limit
/// each key to a single algorithm, as do other DNS implementations.
///
/// [RFC 8945]: https://datatracker.ietf.org/doc/html/rfc8945
pub type TsigKeyMap = HashMap<Box<Name>, (Algorithm, Box<[u8]>)>;

impl<C> Server<C> {
    /// Creates a new `Server` that will serve the provided catalog.
    ///
    /// The default EDNS UDP payload size used is 1,232 octets. This is
    /// the safe default recommended for DNS Flag Day 2020, since 1,232
    /// (DNS message) + 8 (UDP header) + 40 (IPv6 header) = 1,280, the
    /// minimum MTU for IPv6. It should therefore avoid IP packet
    /// fragmentation on almost all present-day networks.
    ///
    /// By default, RRL is disabled. However, public servers should
    /// consider enabling it.
    pub fn new(catalog: Arc<C>) -> Self {
        Self {
            catalog: RwLock::new(catalog),
            edns_udp_payload_size: 1232,
            rrl: None,
            tsig_keys: RwLock::new(Arc::new(TsigKeyMap::new())),
        }
    }

    /// Returns the current catalog of the server.
    pub fn catalog(&self) -> Arc<C> {
        self.catalog.read().unwrap().clone()
    }

    /// Sets the catalog of the `Server`. Some in-flight message
    /// handling may continue to use the old catalog (depending on how
    /// far it has gotten), but handling started after this call
    /// completes will see the new one.
    pub fn set_catalog(&self, catalog: Arc<C>) {
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

    /// Returns the `Server`'s current set of TSIG keys.
    pub fn tsig_keys(&self) -> Arc<TsigKeyMap> {
        self.tsig_keys.read().unwrap().clone()
    }

    /// Sets the `Server`'s set of TSIG keys.
    pub fn set_tsig_keys(&self, tsig_keys: Arc<TsigKeyMap>) {
        *self.tsig_keys.write().unwrap() = tsig_keys;
    }
}

impl<C> Server<C>
where
    C: Catalog,
{
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
        let mut context = Context::new(catalog.as_ref(), received, received_info, response);
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
    fn handle_message_with_context(&self, context: &mut Context<C>) {
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
        // see it in these two sections, return FORMERR. Similarly, RFC
        // 8945 § 5.1 requires that the TSIG record be in the additional
        // section, so if we see it, then that's also a FORMERR.
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
            if matches!(peek_rr.rr_type(), Type::OPT | Type::TSIG) {
                context.response.set_rcode(Rcode::FORMERR);
                return;
            } else {
                peek_rr.skip();
            }
        }

        // Scan the additional section. If we see an OPT or TSIG, now's
        // the time to process it.
        let mut seen_opt = false;
        let arcount = context.received.arcount() as usize;
        for index in 0..arcount {
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
            } else if peek_rr.rr_type() == Type::TSIG {
                // Per RFC 8945 § 5.1, there can be at most one TSIG
                // record, and it must be the final record in the
                // message. Otherwise, we must return FORMERR.
                if index != arcount - 1 {
                    context.response.set_rcode(Rcode::FORMERR);
                    return;
                }

                // Parse the TSIG RR.
                let message_without_tsig = peek_rr.message_to_rr();
                let read_rr = match peek_rr.parse() {
                    Ok(read_rr) => read_rr,
                    Err(_) => {
                        context.response.set_rcode(Rcode::FORMERR);
                        return;
                    }
                };
                let tsig_rr = match ReadTsigRr::try_from(read_rr) {
                    Ok(tsig_rr) => tsig_rr,
                    Err(tsig::FromReadRrError::FormErr) => {
                        context.response.set_rcode(Rcode::FORMERR);
                        return;
                    }
                    Err(tsig::FromReadRrError::NotTsig) => {
                        panic!("tried to parse a non-TSIG record as a TSIG record; this is a bug")
                    }
                };

                // Validate the TSIG RR and add a TSIG RR of our own to
                // the response. (Each step will, upon encountering an
                // error, add a TSIG RR with the appropriate RCODE to
                // the response. Thus, all we need to do here in such
                // cases is to return.)
                let now = SystemTime::now().try_into().expect(
                    "the system time cannot be expressed in the TSIG \"time signed\" field",
                );
                let algorithm = match find_tsig_algorithm_or_write_error(
                    &tsig_rr,
                    now,
                    &mut context.response,
                ) {
                    Some(algorithm) => algorithm,
                    None => return,
                };
                let tsig_keys = self.tsig_keys();
                let key = match find_tsig_key_or_write_error(
                    &tsig_rr,
                    algorithm,
                    &tsig_keys,
                    now,
                    &mut context.response,
                ) {
                    Some(key) => key,
                    None => return,
                };
                if !verify_tsig_and_write_tsig_rr(
                    &tsig_rr,
                    message_without_tsig,
                    algorithm,
                    key,
                    now,
                    &mut context.response,
                ) {
                    return;
                }

                // Validation succeeded. By saving the key name, we
                // indicate that the message successfully authenticated
                // with that key.
                context.tsig_key = Some(tsig_rr.key_name().to_owned());
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
struct Context<'c, 'b, C> {
    // Snapshot of the catalog at the beginning of processing:
    catalog: &'c C,

    // Information on the received message:
    received: Reader<'b>,
    received_info: ReceivedInfo,
    question: Option<Question>,
    tsig_key: Option<Box<LowercaseName>>,

    // Data recorded during processing:
    source_of_synthesis: Option<Cow<'c, Name>>,

    // Information on the response:
    response: Writer<'b>,
    rrl_action: Option<rrl::Action>,
    send_response: bool,
}

impl<'c, 'b, C> Context<'c, 'b, C> {
    /// Creates a new `Context`.
    fn new(
        catalog: &'c C,
        received: Reader<'b>,
        received_info: ReceivedInfo,
        response: Writer<'b>,
    ) -> Self {
        Self {
            catalog,
            received,
            received_info,
            question: None,
            tsig_key: None,
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
// TSIG RECORD HANDLING                                               //
////////////////////////////////////////////////////////////////////////

/// The "fudge" value (in seconds) to use in TSIG responses. This is
/// currently hard-coded to the value recommended by [RFC 8945 § 10].
///
/// [RFC 8945 § 10]: https://datatracker.ietf.org/doc/html/rfc8945#section-10
const TSIG_FUDGE: u16 = 300;

/// Finds the [`Algorithm`] specified by a received TSIG RR. If the
/// algorithm is not recognized, then a TSIG RR with error BADKEY is
/// added to the response and the function returns `None`.
fn find_tsig_algorithm_or_write_error(
    tsig_rr: &ReadTsigRr,
    now: TimeSigned,
    response: &mut Writer,
) -> Option<Algorithm> {
    if let Some(algorithm) = Algorithm::from_name(tsig_rr.algorithm()) {
        Some(algorithm)
    } else {
        response.set_rcode(Rcode::NOTAUTH);
        response
            .set_tsig(
                writer::TsigMode::Unsigned {
                    algorithm: tsig_rr.algorithm().to_owned(),
                },
                PreparedTsigRr::new_from_read(tsig_rr, now, TSIG_FUDGE, ExtendedRcode::BADKEY),
            )
            .unwrap();
        None
    }
}

/// Finds the TSIG key specified by a received TSIG RR. If the key is
/// not recognized, then a TSIG RR with error BADKEY is added to the
/// response and the function returns `None`.
fn find_tsig_key_or_write_error<'k>(
    tsig_rr: &ReadTsigRr,
    algorithm: Algorithm,
    tsig_keys: &'k TsigKeyMap,
    now: TimeSigned,
    response: &mut Writer,
) -> Option<&'k [u8]> {
    // We need to (a) find the key with the name specified by the
    // received TSIG RR, and (b) make sure that the algorithm associated
    // with that key is the one that the other party is using.
    if let Some((_, key)) = tsig_keys
        .get(tsig_rr.key_name().as_ref())
        .filter(|(a, _)| *a == algorithm)
    {
        Some(key)
    } else {
        response.set_rcode(Rcode::NOTAUTH);
        response
            .set_tsig(
                writer::TsigMode::Unsigned {
                    algorithm: tsig_rr.algorithm().to_owned(),
                },
                PreparedTsigRr::new_from_read(tsig_rr, now, TSIG_FUDGE, ExtendedRcode::BADKEY),
            )
            .unwrap();
        None
    }
}

/// Verifies a received message with a TSIG RR. A TSIG RR with the
/// appropriate RCODE is written to the response. Returns whether
/// verification was successful.
///
/// The algorithm and key should match the ones specified by `tsig_rr`
/// and should be found with [`find_tsig_algorithm_or_write_error`] and
/// [`find_tsig_key_or_write_error`], respectively.
fn verify_tsig_and_write_tsig_rr(
    tsig_rr: &ReadTsigRr,
    message_without_tsig: &[u8],
    algorithm: Algorithm,
    key: &[u8],
    now: TimeSigned,
    response: &mut Writer,
) -> bool {
    let (rcode, tsig_err, mode) =
        match tsig_rr.verify_request(message_without_tsig, algorithm, key, now) {
            Ok(()) => (
                Rcode::NOERROR,
                ExtendedRcode::NOERROR,
                writer::TsigMode::Response {
                    request_mac: tsig_rr.mac().into(),
                    algorithm,
                    key: key.into(),
                },
            ),
            Err(tsig::VerificationError::BadSig) => (
                Rcode::NOTAUTH,
                ExtendedRcode::BADVERSBADSIG,
                writer::TsigMode::Unsigned {
                    algorithm: algorithm.name().to_owned(),
                },
            ),
            Err(tsig::VerificationError::BadTime) => (
                Rcode::NOTAUTH,
                ExtendedRcode::BADTIME,
                writer::TsigMode::Response {
                    request_mac: tsig_rr.mac().into(),
                    algorithm,
                    key: key.into(),
                },
            ),
            // The next case occurs when the request MAC does not meet
            // the minimum length requirements of RFC 8945 § 5.2.2.1.
            // The RFC says to return FORMERR, but it's not clear what
            // to do about the TSIG record. We follow BIND and put
            // BADSIG in the TSIG error field.
            Err(tsig::VerificationError::FormErr) => (
                Rcode::FORMERR,
                ExtendedRcode::BADVERSBADSIG,
                writer::TsigMode::Unsigned {
                    algorithm: algorithm.name().to_owned(),
                },
            ),
        };

    response.set_rcode(rcode);
    response
        .set_tsig(
            mode,
            PreparedTsigRr::new_from_read(tsig_rr, now, TSIG_FUDGE, tsig_err),
        )
        .unwrap();
    rcode == Rcode::NOERROR
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
    use crate::db::{HashMapTreeCatalog, HashMapTreeZone};

    type CatalogImpl = HashMapTreeCatalog<HashMapTreeZone, ()>;

    #[test]
    fn set_edns_udp_payload_size_enforces_min() {
        let mut server = Server::new(Arc::new(CatalogImpl::new()));
        assert!(server.set_edns_udp_payload_size(256).is_err());
    }

    #[test]
    #[should_panic(expected = "the response buffer is not large enough")]
    fn handle_message_rejects_short_buffers_for_tcp() {
        let server = Server::new(Arc::new(CatalogImpl::new()));
        let received_info = ReceivedInfo::new(Ipv4Addr::LOCALHOST.into(), Transport::Tcp);
        let mut not_quite_large_enough = [0; u16::MAX as usize - 1];
        server.handle_message(&[], received_info, &mut not_quite_large_enough);
    }

    #[test]
    #[should_panic(expected = "the response buffer is not large enough")]
    fn handle_message_rejects_short_buffers_for_udp() {
        let server = Server::new(Arc::new(CatalogImpl::new()));
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
