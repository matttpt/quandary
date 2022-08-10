// Copyright 2021 Matthew Ingwersen.
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

//! Data structures and routines for handling DNS resource record data.

pub mod rdata;
pub mod rdata_set;
mod rr_type;
mod ttl;
pub use rdata::Rdata;
pub use rdata_set::{RdataSet, RdataSetOwned};
pub use rr_type::Type;
pub use ttl::Ttl;
