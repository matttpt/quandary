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

//! The [`Node`] structure, representing a node in the DNS tree, used in
//! both the [`HashMapTreeCatalog`](super::catalog::HashMapTreeCatalog)
//! and [`HashMapTreeZone`](super::zone::HashMapTreeZone) data
//! structures.

use std::collections::{hash_map, HashMap};
use std::iter::FusedIterator;

use crate::name::{LabelBuf, Name};

/// A node in the DNS tree. This structure is generic over the type of
/// data to store at each node.
#[derive(Clone, Debug)]
pub struct Node<T> {
    pub name: Box<Name>,
    pub children: HashMap<LabelBuf, Node<T>>,
    pub data: T,
}

impl<T: Default> Node<T> {
    /// Creates a new `Node` with the provided name. Its data is set to
    /// `T`'s default, and it initially has no children.
    pub fn new(name: Box<Name>) -> Self {
        Self {
            name,
            data: T::default(),
            children: HashMap::new(),
        }
    }

    /// Gets or creates a descendant node corresponding to `name`. Any
    /// nodes between the target descendant node and `self` will also be
    /// created. `level` should be set so that `self` corresponds to the
    /// label `name[level]`.
    pub fn get_or_create_descendant(&mut self, name: &Name, level: usize) -> &mut Self {
        if level == 0 {
            self
        } else {
            self.children
                .entry(name[level - 1].to_owned())
                .or_insert_with(|| Self::new(name.superdomain(level - 1).unwrap()))
                .get_or_create_descendant(name, level - 1)
        }
    }
}

impl<T> Node<T> {
    /// Returns an iterator over this node and its children.
    pub fn iter(&self) -> Iter<T> {
        Iter::new(self)
    }
}

////////////////////////////////////////////////////////////////////////
// NODE ITERATOR                                                      //
////////////////////////////////////////////////////////////////////////

/// An iterator over a [`Node`] and its children.
pub struct Iter<'a, T> {
    state: IterState<'a, T>,
}

/// The internal state of an [`Iter`].
enum IterState<'a, T> {
    /// The next action is to return the data at the current node.
    Node {
        node: &'a Node<T>,
        stack: IterStack<'a, T>,
    },

    /// The next action is to begin processing the next unprocessed
    /// child of the current node.
    Children {
        children: hash_map::Values<'a, LabelBuf, Node<T>>,
        stack: IterStack<'a, T>,
    },

    /// Iteration is complete.
    Finished,
}

type IterStack<'a, T> = Vec<hash_map::Values<'a, LabelBuf, Node<T>>>;

impl<'a, T> Iter<'a, T> {
    /// Creates a new `Iter` that will iterate over the provided node.
    fn new(apex: &'a Node<T>) -> Self {
        Self {
            state: IterState::Node {
                node: apex,
                stack: Vec::new(),
            },
        }
    }

    /// Acts on the current state of the iterator. Returns the next
    /// value to return from [`Iterator::next`], or `None` if the state
    /// transition did not produce a new value. In the latter case, this
    /// method should be called repeatedly until it produces a value.
    fn execute_state_machine(&mut self) -> Option<Option<(&'a Name, &'a T)>> {
        let previous_state = std::mem::replace(&mut self.state, IterState::Finished);
        match previous_state {
            IterState::Node { node, stack } => {
                self.state = IterState::Children {
                    children: node.children.values(),
                    stack,
                };
                Some(Some((&node.name, &node.data)))
            }
            IterState::Children {
                mut children,
                mut stack,
            } => {
                if let Some(next_child) = children.next() {
                    stack.push(children);
                    self.state = IterState::Node {
                        node: next_child,
                        stack,
                    };
                    None
                } else if let Some(parent) = stack.pop() {
                    self.state = IterState::Children {
                        children: parent,
                        stack,
                    };
                    None
                } else {
                    Some(None)
                }
            }
            IterState::Finished => Some(None),
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = (&'a Name, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(result) = self.execute_state_machine() {
                return result;
            }
        }
    }
}

impl<'a, T> FusedIterator for Iter<'a, T> {}
