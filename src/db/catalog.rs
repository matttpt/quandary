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

//! The [`Catalog`] trait and associated types.

use std::sync::Arc;

use crate::class::Class;
use crate::name::Name;

use super::Zone;

/// Trait for catalog data sources.
///
/// A [catalog][RFC 1035 § 6.1.2] is the collection of all zones for
/// which a server is authoritative. The essential operation on a
/// catalog is searching for the zone that should be used to answer
/// queries for a given domain name and DNS class; see
/// [`Catalog::lookup`].
///
/// See the [`db` module documentation](crate::db#zones-and-catalogs)
/// for more information.
///
/// [RFC 1035 § 6.1.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-6.1.2
pub trait Catalog {
    /// Metadata attached to each entry.
    type Metadata;

    /// The zone data source type ([`Zone`] implementation) that this
    /// catalog returns.
    type ZoneImpl: Zone;

    /// Within the given DNS class, looks up the zone in the catalog
    /// that is the nearest ancestor to `name` (i.e., the zone whose
    /// name matches the most consecutive labels in `name`, starting
    /// from the right). This is step 2 of the lookup algorithm given
    /// in [RFC 1034 § 4.3.2].
    ///
    /// [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
    fn lookup(&self, name: &Name, class: Class) -> Option<&Entry<Self::ZoneImpl, Self::Metadata>>;

    /// Within the given DNS class, finds the zone associated
    /// with the provided domain name. Unlike [`Catalog::lookup`], the
    /// entry's name must match exactly.
    ///
    /// A default implementation that uses [`Catalog::lookup`] is
    /// provided. However, `Catalog` implementers may wish to provide a
    /// custom version if [`Catalog::lookup`] requires significantly
    /// more work than required to implement `get`.
    fn get(&self, name: &Name, class: Class) -> Option<&Entry<Self::ZoneImpl, Self::Metadata>> {
        self.lookup(name, class)
            .filter(|entry| entry.name().len() == name.len())
    }
}

/// An entry in a catalog of zones.
///
/// An `Entry` at a domain name indicates that the server is
/// authoritative for a zone whose apex is that domain. It may include a
/// [`Zone`] data source, or it may be a placeholder indicating that the
/// zone has not yet been loaded or that the zone failed to load. In
/// each case, it also includes metadata that users can attach to the
/// zone.
#[derive(Debug)]
pub enum Entry<Z, M> {
    Loaded(Arc<Z>, M),
    NotYetLoaded(Box<Name>, Class, M),
    FailedToLoad(Box<Name>, Class, M),
}

impl<Z, M> Entry<Z, M>
where
    Z: Zone,
{
    /// Returns the class of the zone or placeholder in this entry.
    pub fn class(&self) -> Class {
        match self {
            Self::Loaded(zone, _) => zone.class(),
            Self::NotYetLoaded(_, class, _) | Self::FailedToLoad(_, class, _) => *class,
        }
    }

    /// Returns the name of the zone or placeholder in this entry.
    pub fn name(&self) -> &Name {
        match self {
            Self::Loaded(zone, _) => zone.name(),
            Self::NotYetLoaded(name, _, _) | Self::FailedToLoad(name, _, _) => name,
        }
    }

    /// Returns the metadata associated with this entry.
    pub fn metadata(&self) -> &M {
        match self {
            Self::Loaded(_, meta) => meta,
            Self::NotYetLoaded(_, _, meta) | Self::FailedToLoad(_, _, meta) => meta,
        }
    }
}

impl<Z, M> Clone for Entry<Z, M>
where
    M: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::Loaded(zone, meta) => Self::Loaded(zone.clone(), meta.clone()),
            Self::NotYetLoaded(name, class, meta) => {
                Self::NotYetLoaded(name.clone(), *class, meta.clone())
            }
            Self::FailedToLoad(name, class, meta) => {
                Self::FailedToLoad(name.clone(), *class, meta.clone())
            }
        }
    }
}
