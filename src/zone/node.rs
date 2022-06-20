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

//! Implementation of the the [`Node`] structure for DNS tree data
//! structures.

use std::collections::HashMap;

use crate::name::{LabelBuf, Name};

/// A node in the DNS tree. This structure is generic over the type of
/// data to store at each node.
#[derive(Debug)]
pub(super) struct Node<T> {
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
