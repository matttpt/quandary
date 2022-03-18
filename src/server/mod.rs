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

use crate::message::{writer, Opcode, Question, Rcode, Reader, Writer};
use crate::zone::Zone;

use log::error;

mod query;

////////////////////////////////////////////////////////////////////////
// SERVER PUBLIC API                                                  //
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
/// The [`Server`] in turn produces responses based on its catalog of
/// [`Zone`]s loaded into memory. Currently, only one [`Zone`] is
/// supported. A [`Server`] is created to serve a [`Zone`] with
/// [`Server::new`].
pub struct Server {
    zone: Zone,
}

impl Server {
    /// Creates a new `Server` that will serve the provided [`Zone`].
    pub fn new(zone: Zone) -> Self {
        Self { zone }
    }

    /// Handles a received DNS message. This is the API through which
    /// I/O providers submit messages.
    ///
    /// `received_buf` contains the message received. `response_buf` is
    /// a buffer into which a response message may be serialized. Its
    /// length is interpreted as the maximum size of a DNS message the
    /// caller is willing to send. To comply with the DNS specification,
    /// it should be at least 512 octets long for UDP transport. For TCP
    /// transport, the maximum possible size (65,535 octets) should be
    /// used. `over_tcp` specifies whether the underlying transport was
    /// TCP (`true`) or UDP (`false`).
    ///
    /// A [`Response`] is returned, signifying whether a response is to
    /// be sent and, if so, how long the response message written into
    /// `response_buf` is.
    pub fn handle_message(
        &self,
        received_buf: &[u8],
        response_buf: &mut [u8],
        over_tcp: bool,
    ) -> Response {
        if let Ok(received) = Reader::try_from(received_buf) {
            // We currently only support standard queries.
            if received.opcode() == Opcode::Query {
                self.handle_query(received, response_buf, over_tcp)
            } else {
                generate_error(&received, None, Rcode::NotImp, response_buf)
            }
        } else {
            // Ignore messages that do not contain a full DNS header.
            Response::None
        }
    }
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
// HELPERS TO PREPARE RESPONSE MESSAGES                               //
////////////////////////////////////////////////////////////////////////

/// Prepares the header of `response` from the header of `received`.
/// The message ID, RD bit, and opcode are copied from `received`, and
/// the query response (QR) bit is set.
fn set_up_response_header(received: &Reader, response: &mut Writer) {
    response.set_id(received.id());
    response.set_qr(true);
    response.set_rd(received.rd());
    response.set_opcode(received.opcode());
}

/// Writes an error response with the given RCODE and (optionally)
/// question into the provided buffer, producing a [`Response`].
///
/// This is intended for use early on in processing, when a response
/// [`Writer`] has not yet been set up.
fn generate_error(
    received: &Reader,
    question: Option<&Question>,
    rcode: Rcode,
    response_buf: &mut [u8],
) -> Response {
    if let Ok(response_len) = try_generating_error(received, question, rcode, response_buf) {
        Response::Single(response_len)
    } else {
        error!("try_generating_error failed. This is a bug.");
        Response::None
    }
}

/// Attempts to write an error response with the given RCODE and
/// (optionally) question into the provided buffer.
fn try_generating_error(
    received: &Reader,
    question: Option<&Question>,
    rcode: Rcode,
    response_buf: &mut [u8],
) -> writer::Result<usize> {
    let mut response = Writer::try_from(response_buf)?;
    set_up_response_header(received, &mut response);
    response.set_rcode(rcode);
    if let Some(question) = question {
        response.add_question(question)?;
    }
    Ok(response.finish())
}

/// Converts an existing response into a SERVFAIL response.
fn reconfigure_as_servfail(response: &mut Writer) {
    // Processing code may have set the AA bit, so we clear it here.
    response.set_aa(false);
    response.set_rcode(Rcode::ServFail);
    response.clear_rrs();
}

/// Checks `processing_result` and, if it is an error, modifies the
/// response accordingly.
///
/// * If the error is a truncation error and the transport is UDP, the
///   message's RRs are cleared and the TC bit is set.
/// * If the error is a truncation error and the transport is TCP,
///   retrying over TCP won't help. The message is converted into a
///   SERVFAIL response.
/// * For all other errors, the message is converted into a SERVFAIL
///   response.
fn handle_processing_errors(
    processing_result: ProcessingResult<()>,
    response: &mut Writer,
    over_tcp: bool,
) {
    match processing_result {
        Ok(()) => (),
        Err(ProcessingError::ServFail) => reconfigure_as_servfail(response),
        Err(ProcessingError::Truncation) => {
            if over_tcp {
                // We can't ask the client to retry over TCP, since
                // we are already over TCP.
                reconfigure_as_servfail(response);
            } else {
                response.clear_rrs();
                response.set_tc(true);
            }
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
