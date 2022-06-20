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

//! Implementation of the [`Catalog`] structure.

use std::collections::HashMap;

use super::{Node, Zone};
use crate::class::Class;
use crate::name::Name;

/// A data structure containing all of the zones served by a server.
///
/// A `Catalog` maintains a DNS tree structure and places zones at nodes
/// according to their names. This makes it simple to look up the zone
/// that is the nearest ancestor to any domain name (see
/// [`Catalog::lookup`]).
#[derive(Default)]
pub struct Catalog {
    roots_by_class: HashMap<Class, CatalogNode>,
}

type CatalogNode = Node<Option<Zone>>;

impl Catalog {
    /// Creates a new, initially empty `Catalog`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `zone` to the catalog, replacing and returning the
    /// preexisting [`Zone`] of that name (if any).
    pub fn replace(&mut self, zone: Zone) -> Option<Zone> {
        let root = self
            .roots_by_class
            .entry(zone.class())
            .or_insert_with(|| CatalogNode::new(Name::root().to_owned()));
        let node = root.get_or_create_descendant(zone.name(), zone.name().len() - 1);
        node.data.replace(zone)
    }

    /// Looks up the [`Zone`] in the `Catalog` that is the nearest
    /// ancestor to `name` (i.e., the [`Zone`] whose name matches the
    /// most consecutive labels in `name`, starting from the right).
    /// This is step 2 of the lookup algorithm given in
    /// [RFC 1034 § 4.3.2].
    ///
    /// [RFC 1034 § 4.3.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.2
    pub fn lookup(&self, name: &Name, class: Class) -> Option<&Zone> {
        let root = self.roots_by_class.get(&class)?;
        lookup_in_class(root, name, name.len() - 1)
    }
}

/// Implements catalog lookup. The parameter `node` is the deepest node
/// we have matched so far; this node corresponds to `name[level]`.
fn lookup_in_class<'a>(node: &'a CatalogNode, name: &Name, level: usize) -> Option<&'a Zone> {
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
    use super::super::GluePolicy;
    use super::*;

    #[test]
    fn lookup_works() {
        let test: Box<Name> = "test.".parse().unwrap();
        let quandary_test: Box<Name> = "quandary.test.".parse().unwrap();
        let x_quandary_test: Box<Name> = "x.quandary.test.".parse().unwrap();
        let y_x_quandary_test: Box<Name> = "y.x.quandary.test.".parse().unwrap();

        let mut catalog = Catalog::new();
        let test_zone = Zone::new(test.clone(), Class::IN, GluePolicy::Narrow);
        let x_quandary_test_zone =
            Zone::new(x_quandary_test.clone(), Class::IN, GluePolicy::Narrow);
        catalog.replace(test_zone);
        catalog.replace(x_quandary_test_zone);

        assert!(catalog.lookup(Name::root(), Class::IN).is_none());
        assert_eq!(catalog.lookup(&test, Class::IN).unwrap().name(), &*test);
        assert_eq!(
            catalog.lookup(&quandary_test, Class::IN).unwrap().name(),
            &*test,
        );
        assert_eq!(
            catalog.lookup(&x_quandary_test, Class::IN).unwrap().name(),
            &*x_quandary_test,
        );
        assert_eq!(
            catalog
                .lookup(&y_x_quandary_test, Class::IN)
                .unwrap()
                .name(),
            &*x_quandary_test,
        );
    }
}
