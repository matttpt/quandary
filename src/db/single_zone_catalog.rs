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

//! The [`SingleZoneCatalog`] structure.

use crate::class::Class;
use crate::name::Name;

use super::catalog::Entry;
use super::{Catalog, Zone};

/// A [`Catalog`] data structure that contains a single zone.
pub struct SingleZoneCatalog<Z, M> {
    entry: Entry<Z, M>,
}

impl<Z, M> SingleZoneCatalog<Z, M> {
    /// Creates a new `SingleZoneCatalog` with the provided [`Entry`].
    pub fn new(entry: Entry<Z, M>) -> Self {
        Self { entry }
    }

    /// Returns the catalog's sole entry.
    pub fn entry(&self) -> &Entry<Z, M> {
        &self.entry
    }
}

impl<Z, M> Catalog for SingleZoneCatalog<Z, M>
where
    Z: Zone,
{
    type Metadata = M;
    type ZoneImpl = Z;

    fn lookup(&self, name: &Name, class: Class) -> Option<&Entry<Z, M>> {
        (self.entry.class() == class && name.eq_or_subdomain_of(self.entry.name()))
            .then_some(&self.entry)
    }

    fn get(&self, name: &Name, class: Class) -> Option<&Entry<Z, M>> {
        (self.entry.class() == class && name == self.entry.name()).then_some(&self.entry)
    }
}

impl<Z, M> Clone for SingleZoneCatalog<Z, M>
where
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            entry: self.entry.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::super::HashMapTreeZone;
    use super::*;

    lazy_static! {
        static ref TEST: Box<Name> = "test.".parse().unwrap();
        static ref QUANDARY_TEST: Box<Name> = "quandary.test.".parse().unwrap();
        static ref SUB_QUANDARY_TEST: Box<Name> = "sub.quandary.test.".parse().unwrap();
        static ref CATALOG: SingleZoneCatalog<HashMapTreeZone, ()> =
            SingleZoneCatalog::new(Entry::NotYetLoaded(QUANDARY_TEST.clone(), Class::IN, ()));
    }

    #[test]
    fn lookup_works() {
        assert!(CATALOG.lookup(&TEST, Class::IN).is_none());
        assert!(matches!(
            CATALOG.lookup(&QUANDARY_TEST, Class::IN),
            Some(Entry::NotYetLoaded(n, c, ())) if *n == *QUANDARY_TEST && *c == Class::IN,
        ));
        assert!(matches!(
            CATALOG.lookup(&SUB_QUANDARY_TEST, Class::IN),
            Some(Entry::NotYetLoaded(n, c, ())) if *n == *QUANDARY_TEST && *c == Class::IN,
        ));
        assert!(CATALOG.lookup(&QUANDARY_TEST, Class::HS).is_none());
    }

    #[test]
    fn get_works() {
        assert!(CATALOG.get(&TEST, Class::IN).is_none());
        assert!(matches!(
            CATALOG.get(&QUANDARY_TEST, Class::IN),
            Some(Entry::NotYetLoaded(n, c, ())) if *n == *QUANDARY_TEST && *c == Class::IN,
        ));
        assert!(CATALOG.get(&SUB_QUANDARY_TEST, Class::IN).is_none());
        assert!(CATALOG.get(&QUANDARY_TEST, Class::HS).is_none());
    }
}
