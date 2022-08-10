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

//! The [`HashMapTreeCatalog`] structure.

use std::collections::HashMap;

use crate::class::Class;
use crate::db::catalog::{Catalog, Entry};
use crate::db::Zone;
use crate::name::Name;

/// An in-memory [`Catalog`] data structure that mirrors the DNS's tree
/// structure and stores the children of each node in a [`HashMap`].
///
/// A `HashMapTreeCatalog` keeps a catalog of zones in memory using the
/// same underlying data structures as [`HashMapTreeZone`]. It offers
/// good performance, and furthermore, since it replicates the DNS's
/// tree structure, it's a good reference implementation.
///
/// [`HashMap`]: std::collections::HashMap
/// [`HashMapTreeZone`]: super::super::HashMapTreeZone
pub struct HashMapTreeCatalog<Z, M> {
    roots_by_class: HashMap<Class, Node<Z, M>>,
}

type Node<Z, M> = super::node::Node<Option<Entry<Z, M>>>;

impl<Z, M> HashMapTreeCatalog<Z, M> {
    /// Creates a new, initially empty `Catalog`.
    pub fn new() -> Self {
        Self {
            roots_by_class: HashMap::new(),
        }
    }
}

impl<Z, M> Default for HashMapTreeCatalog<Z, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Z, M> HashMapTreeCatalog<Z, M>
where
    Z: Zone,
{
    /// Adds an [`Entry`] to the `Catalog`, replacing and returning the
    /// current [`Entry`] at that name (if any).
    pub fn insert(&mut self, entry: Entry<Z, M>) -> Option<Entry<Z, M>> {
        let root = self
            .roots_by_class
            .entry(entry.class())
            .or_insert_with(|| Node::new(Name::root().to_owned()));
        let node = root.get_or_create_descendant(entry.name(), entry.name().len() - 1);
        node.data.replace(entry)
    }
}

impl<Z, M> Catalog for HashMapTreeCatalog<Z, M>
where
    Z: Zone,
{
    type Metadata = M;
    type ZoneImpl = Z;

    fn lookup(&self, name: &Name, class: Class) -> Option<&Entry<Z, M>> {
        let root = self.roots_by_class.get(&class)?;
        lookup_in_class(root, name, name.len() - 1)
    }
}

/// Implements catalog lookup. The parameter `node` is the deepest node
/// we have matched so far; this node corresponds to `name[level]`.
fn lookup_in_class<'a, Z, M>(
    node: &'a Node<Z, M>,
    name: &Name,
    level: usize,
) -> Option<&'a Entry<Z, M>> {
    if level == 0 {
        // We've matched the entire name.
        node.data.as_ref()
    } else {
        // Try to traverse down the tree. If we can match more labels,
        // then we see if there's a longer match.
        let longer_match = if let Some(subnode) = node.children.get(&name[level - 1]) {
            lookup_in_class(subnode, name, level - 1)
        } else {
            None
        };
        longer_match.or(node.data.as_ref())
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::zone::HashMapTreeZone;
    use super::*;
    use crate::db::zone::GluePolicy;

    #[test]
    fn lookup_works() {
        let test: Box<Name> = "test.".parse().unwrap();
        let quandary_test: Box<Name> = "quandary.test.".parse().unwrap();
        let x_quandary_test: Box<Name> = "x.quandary.test.".parse().unwrap();
        let y_x_quandary_test: Box<Name> = "y.x.quandary.test.".parse().unwrap();

        let mut catalog = HashMapTreeCatalog::new();
        let test_zone = HashMapTreeZone::new(test.clone(), Class::IN, GluePolicy::Narrow);
        catalog.insert(Entry::Loaded(Arc::new(test_zone), ()));
        catalog.insert(Entry::NotYetLoaded(x_quandary_test.clone(), Class::IN, ()));

        assert!(catalog.lookup(Name::root(), Class::IN).is_none());
        assert!(matches!(
            catalog.lookup(&test, Class::IN),
            Some(Entry::Loaded(zone, _)) if zone.name() == &*test,
        ));
        assert!(matches!(
            catalog.lookup(&quandary_test, Class::IN),
            Some(Entry::Loaded(zone, _)) if zone.name() == &*test,
        ));
        assert!(matches!(
            catalog.lookup(&x_quandary_test, Class::IN),
            Some(Entry::NotYetLoaded(name, _, _)) if name == &x_quandary_test,
        ));
        assert!(matches!(
            catalog.lookup(&y_x_quandary_test, Class::IN),
            Some(Entry::NotYetLoaded(name, _, _)) if name == &x_quandary_test,
        ));
    }
}
