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

//! Constants related to DNS messages.

pub const HEADER_SIZE: usize = 12;
pub const ID_START: usize = 0;
pub const ID_END: usize = 2;
pub const QR_BYTE: usize = 2;
pub const QR_MASK: u8 = 0x80;
pub const OPCODE_BYTE: usize = 2;
pub const OPCODE_MASK: u8 = 0x78;
pub const OPCODE_SHIFT: usize = 3;
pub const AA_BYTE: usize = 2;
pub const AA_MASK: u8 = 0x04;
pub const TC_BYTE: usize = 2;
pub const TC_MASK: u8 = 0x02;
pub const RD_BYTE: usize = 2;
pub const RD_MASK: u8 = 0x01;
pub const RA_BYTE: usize = 3;
pub const RA_MASK: u8 = 0x80;
pub const RCODE_BYTE: usize = 3;
pub const RCODE_MASK: u8 = 0x0f;
pub const QDCOUNT_START: usize = 4;
pub const QDCOUNT_END: usize = 6;
pub const ANCOUNT_START: usize = 6;
pub const ANCOUNT_END: usize = 8;
pub const NSCOUNT_START: usize = 8;
pub const NSCOUNT_END: usize = 10;
pub const ARCOUNT_START: usize = 10;
pub const ARCOUNT_END: usize = 12;
pub const POINTER_MAX: usize = 16383;
