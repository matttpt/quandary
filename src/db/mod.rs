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

//! Facilities for storing and accessing DNS data.
//!
//! The DNS is essentially a distributed database, and authoritative
//! server implementations are thus database software of a sort. The
//! core of this module is the [`Catalog`] and [`Zone`] traits, which
//! abstract DNS database operations such as record lookups from the
//! actual storage methods and algorithms used. For instance, different
//! implementations of the [`Zone`] trait may keep DNS data in memory
//! using different data structures, read it from an on-disk database
//! file, access an SQL database over the network, or even forward all
//! lookups to another DNS server.
//!
//! ## Zones and catalogs
//!
//! While [RFC 1035 § 6.1.2] notes that a server may use any internal
//! data structures, a tiered approach is suggested. At the first level,
//! the server maintains a "catalog" data structure that contains the
//! zones for which the server is authoritative. Each zone is in turn
//! stored in its own data structure.
//!
//! [RFC 1034 § 4.3.2] provides a conceptual algorithm for answering DNS
//! queries that is again based on this two-tiered approach. In step 2
//! (the first substantive step), the zone to which the query pertains
//! is identified. In step 3, the zone is searched for the desired
//! records.
//!
//! Even if the underlying data structures for a server's database do
//! not follow this tiered system, it's still important conceptually. As
//! noted above, the DNS lookup algorithm is described with this
//! distinction. Furthermore, DNS operations frequently require
//! consideration of a zone as a unit. For instance, zone transfers
//! (AXFR and IXFR), DNSSEC signing, and various semantic checks operate
//! on entire zones. Furthermore, nameserver operators often use
//! per-zone configurations, such as ACLs for zone transfers. Finally,
//! it is a design goal of this software to allow the same server to
//! simultaneously serve zones with different backends.
//!
//! Therefore, Quandary's database interfaces use the two-step lookup
//! procedure suggested by the RFCs. The two steps are codified by the
//! [`Catalog`] and [`Zone`] traits.
//!
//! All this is not to say that users cannot write [`Catalog`] and
//! [`Zone`] implementations that are backed by a flat database of DNS
//! records! It's merely required that the database be correctly exposed
//! to Quandary through the two-step interface.
//!
//! ## Provided in-memory database structures
//!
//! "Traditional" authoritative server implementations generally load
//! their databases entirely into memory; indeed, the discussion in
//! [RFC 1035 § 6.1.2] seems to assume that this is the case! Even after
//! several decades, this is still a perfectly good strategy for most
//! use-cases. To this end, we provide ready-made implementations of the
//! [`Catalog`] and [`Zone`] traits that store their data in memory.
//! (These are what the Quandary daemon uses.)
//!
//! Currently, the [`HashMapTreeCatalog`] and [`HashMapTreeZone`] are
//! available. These both use a tree structure that mirrors the DNS
//! namespace's tree. The children of each node are stored in a hash
//! map, whence the name. Notably, this implementation is essentially
//! the one suggested in [RFC 1035 § 6.1.2], and the lookup algorithms
//! are more or less a transcription of [RFC 1034 § 4.3.2]. Thus, these
//! types are a good reference for those looking to understand the DNS
//! lookup process! Moreover, they offer good performance. However, the
//! [`HashMapTreeZone`] is not suitable for DNSSEC-enabled zones, since
//! DNSSEC processing requires ordered accesses, which the underlying
//! hash maps cannot provide.
//!
//! [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
//! [RFC 1035 § 6.1.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-6.1.2

pub mod catalog;
mod error;
mod hash_map_tree;
mod rrset;
pub mod zone;

pub use catalog::Catalog;
pub use error::Error;
pub use hash_map_tree::catalog::HashMapTreeCatalog;
pub use hash_map_tree::zone::HashMapTreeZone;
pub use zone::Zone;
