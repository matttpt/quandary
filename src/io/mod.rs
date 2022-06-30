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

//! I/O providers for running [`Server`s](crate::server::Server).
//!
//! The [`Server`](crate::server::Server) structure and its methods
//! implement the processing logic of an authoritative DNS server
//! abstracted from underlying network I/O. Therefore, to actually run a
//! [`Server`](crate::server::Server), an I/O provider is needed.
//!
//! This module implements various network I/O providers for this
//! purpose. The providers take a [`Server`](crate::server::Server) and,
//! when run, act as the intermediary between operating system network
//! and I/O APIs on one hand and the [`Server`](crate::server::Server)
//! on the other. The primary differences between them are the network
//! and I/O APIs used and their concurrency strategies (based on what is
//! appropriate for those APIs).

mod blocking;
pub mod socket;

pub use blocking::{BlockingIoConfig, BlockingIoProvider};
