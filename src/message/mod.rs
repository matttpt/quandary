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

//! Implementation of reading and writing of DNS messages.

mod constants;
mod opcode;
mod question;
mod rcode;
pub mod reader;
pub mod tsig;
pub mod writer;
pub use opcode::{IntoOpcodeError, Opcode};
pub use question::{Qclass, Qtype, Question};
pub use rcode::{ExtendedRcode, IntoRcodeError, Rcode};
pub use reader::Reader;
pub use writer::Writer;
