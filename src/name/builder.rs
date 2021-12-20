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

//! Implementation of the [`NameBuilder`] structure.

use std::convert::TryInto;

use arrayvec::ArrayVec;

use super::{new_boxed_name, Error, Name, MAX_LABEL_LEN, MAX_N_LABELS, MAX_WIRE_LEN};

/// A facility to efficiently build boxed [`Name`]s.
///
/// The `NameBuilder` constructs the on-the-wire representation and
/// label offset array for a [`Name`] using fixed-size internal buffers
/// that are long enough to accomodate any valid name. If the
/// `NameBuilder` is placed on the stack, then construction of a
/// `Box<Name>` (for instance, when parsing a textual representation
/// while reading a zone file) is fast, requiring only one final heap
/// allocation and copy when the name is finished.
///
/// A new `NameBuilder` starts with a single null label. If the build is
/// finished at this point, the name of the DNS root is constructed:
///
/// ```
/// use quandary::name::{Name, NameBuilder};
/// assert_eq!(NameBuilder::new().finish().unwrap().as_ref(), Name::root());
/// ```
///
/// Single octets can be added to the most recent name using
/// [`NameBuilder::try_push`]. Multiple octets can be added at a time
/// using [`NameBuilder::try_push_slice`]. A new label is started using
/// [`NameBuilder::next_label`]. If any call to these methods would
/// result in an invalid domain name, an error is returned.
///
/// A `Box<Name>` is finally constructed with the
/// [`NameBuilder::finish`] method. Alternatively,
/// [`NameBuilder::finish_with_suffix`] may be used to complete the
/// domain name with another domain name, thereby creating a subdomain
/// of the latter.
///
/// Example usage:
///
/// ```
/// use quandary::name::{Name, NameBuilder};
/// let mut builder = NameBuilder::new();
/// for c in b"exam" {
///     builder.try_push(*c).unwrap();
/// }
/// builder.try_push_slice(b"ple").unwrap();
/// builder.next_label().unwrap();
/// builder.try_push_slice(b"test").unwrap();
/// builder.next_label().unwrap(); // start the null label
/// assert_eq!(builder.finish().unwrap(), "example.test.".parse().unwrap());
/// ```
pub struct NameBuilder {
    wire_repr: ArrayVec<u8, MAX_WIRE_LEN>,
    label_offsets: ArrayVec<u8, MAX_N_LABELS>,
    label_start: usize,
    label_len: u8,
}

impl NameBuilder {
    /// Constructs a new `NameBuilder`, which initially contains a
    /// single null label.
    pub fn new() -> Self {
        Self {
            wire_repr: [0][..].try_into().unwrap(),
            label_offsets: [0][..].try_into().unwrap(),
            label_start: 0,
            label_len: 0,
        }
    }

    /// Determines whether the name currently stored in the
    /// `NameBuilder` is a fully qualified domain name—that is, whether
    /// it ends with the null label.
    pub fn is_fully_qualified(&self) -> bool {
        self.label_len == 0
    }

    /// Tries to add the given octet to the current label. This will
    /// fail if doing so would make the label or name too long. In the
    /// error case, the `NameBuilder`'s state remains unchanged.
    pub fn try_push(&mut self, octet: u8) -> Result<(), Error> {
        if self.label_len >= (MAX_LABEL_LEN as u8) {
            Err(Error::LabelTooLong)
        } else if self.wire_repr.try_push(octet).is_ok() {
            self.label_len += 1;
            Ok(())
        } else {
            Err(Error::NameTooLong)
        }
    }

    // Tries to add the given slice to the current label. This will
    // fail if doing so would make the label or name too long. In the
    // error case, the `NameBuilder`'s state remains unchanged.
    pub fn try_push_slice(&mut self, octets: &[u8]) -> Result<(), Error> {
        if (self.label_len as usize) + octets.len() > MAX_LABEL_LEN {
            Err(Error::LabelTooLong)
        } else if self.wire_repr.try_extend_from_slice(octets).is_ok() {
            self.label_len += octets.len() as u8;
            Ok(())
        } else {
            Err(Error::NameTooLong)
        }
    }

    /// Writes out the length of the current label in the on-the-wire
    /// representation.
    fn update_label_len(&mut self) {
        self.wire_repr[self.label_start] = self.label_len;
    }

    /// Finishes the current label and starts a new one. If the current
    /// label is null, this fails, since only the last label in a domain
    /// name may be null. Likewise, if this makes the domain name too
    /// long, this fails. In the error case, the `NameBuilder`'s state
    /// remains unchanged.
    pub fn next_label(&mut self) -> Result<(), Error> {
        if self.is_fully_qualified() {
            Err(Error::NullNonTerminal)
        } else if self.wire_repr.is_full() {
            Err(Error::NameTooLong)
        } else {
            self.update_label_len();
            self.label_start = self.wire_repr.len();
            self.label_len = 0;

            // The wire_repr push will not fail because we checked that
            // it is not full. The label_offsets push will not fail
            // because we're checking the validity of the name as we go;
            // in particular, if we reach this point, none of the
            // previous labels written is null. Therefore, we will not
            // have exceeded the maximum number of labels in a name.
            self.wire_repr.push(0);
            self.label_offsets.push(self.label_start as u8);
            Ok(())
        }
    }

    /// Finishes the construction of the domain name, returning the
    /// final boxed [`Name`] and consuming the `NameBuilder`. This
    /// implicitly finishes the current label. Since the last label of
    /// a domain name must be null, this fails if that is not the case.
    pub fn finish(self) -> Result<Box<Name>, Error> {
        if !self.is_fully_qualified() {
            Err(Error::NonNullTerminal)
        } else {
            unsafe {
                // SAFETY: we promise that we're passing a valid
                // on-the-wire representation and correct label offsets.
                Ok(new_boxed_name(
                    self.wire_repr.len(),
                    &self.label_offsets,
                    &[&self.wire_repr],
                ))
            }
        }
    }

    /// Finishes the construction of the domain name by implicitly
    /// finishing the current label and then appending the labels of the
    /// domain name `suffix`. The `NameBuilder` itself is consumed.
    /// Since only the last label of a domain name may be null, this
    /// fails if the current label is null. It also fails if appending
    /// `suffix` would make the name too long.
    pub fn finish_with_suffix(mut self, suffix: &Name) -> Result<Box<Name>, Error> {
        if self.is_fully_qualified() {
            Err(Error::NullNonTerminal)
        } else {
            self.update_label_len();
            let label_offset_base = self.wire_repr.len() as u8;
            for label in suffix.labels() {
                self.wire_repr
                    .try_push(label.len() as u8)
                    .map_err(|_| Error::NameTooLong)?;
                self.wire_repr
                    .try_extend_from_slice(label.octets())
                    .map_err(|_| Error::NameTooLong)?;
            }
            for offset in suffix.label_offsets() {
                // The push will not fail, since we checked the validity
                // of the name as we went, and label_offsets has enough
                // room to store the label offsets for any valid name.
                self.label_offsets.push(*offset + label_offset_base);
            }
            unsafe {
                // SAFETY: we promise that we're passing a valid
                // on-the-wire representation and correct label offsets.
                Ok(new_boxed_name(
                    self.wire_repr.len(),
                    &self.label_offsets,
                    &[&self.wire_repr],
                ))
            }
        }
    }
}

impl Default for NameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namebuilder_works() {
        let mut builder = NameBuilder::new();
        for c in b"example".iter() {
            builder.try_push(*c).unwrap();
        }
        builder.next_label().unwrap();
        builder.try_push_slice(b"test").unwrap();
        builder.next_label().unwrap();
        let name = builder.finish().unwrap();
        assert_eq!(name, "example.test.".parse().unwrap());
    }

    #[test]
    fn namebuilder_works_with_suffix() {
        let mut builder = NameBuilder::new();
        let suffix: Box<Name> = "test.".parse().unwrap();
        builder.try_push_slice(b"example").unwrap();
        let name = builder.finish_with_suffix(&suffix).unwrap();
        assert_eq!(name, "example.test.".parse().unwrap());
    }

    #[test]
    fn finish_rejects_non_fqdn() {
        let mut builder = NameBuilder::new();
        builder.try_push(b'x').unwrap();
        assert_eq!(builder.finish(), Err(Error::NonNullTerminal));
    }

    #[test]
    fn finish_with_suffix_rejects_fqdn() {
        let mut builder = NameBuilder::new();
        let suffix: Box<Name> = "test.".parse().unwrap();
        builder.try_push(b'x').unwrap();
        builder.next_label().unwrap();
        assert_eq!(
            builder.finish_with_suffix(&suffix),
            Err(Error::NullNonTerminal)
        );
    }

    #[test]
    fn is_fully_qualified_works() {
        let mut builder = NameBuilder::new();
        assert!(builder.is_fully_qualified());
        builder.try_push(b'x').unwrap();
        assert!(!builder.is_fully_qualified());
        builder.next_label().unwrap();
        assert!(builder.is_fully_qualified());
    }

    #[test]
    fn try_push_rejects_long_label() {
        let mut builder = NameBuilder::new();
        for _ in 0..MAX_LABEL_LEN {
            builder.try_push(b'x').unwrap();
        }
        assert_eq!(builder.try_push(b'x'), Err(Error::LabelTooLong));
    }

    #[test]
    fn try_push_rejects_long_name() {
        let mut builder = NameBuilder::new();
        for _ in 0..MAX_N_LABELS - 1 {
            builder.try_push(b'x').unwrap();
            builder.next_label().unwrap();
        }

        // We are now on the MAX_N_LABELS-th label. There is only space
        // for it to be the null label, so the next call should fail.
        assert_eq!(builder.try_push(b'x'), Err(Error::NameTooLong));
    }

    #[test]
    fn try_push_slice_rejects_long_label() {
        let mut builder = NameBuilder::new();
        for _ in 0..MAX_LABEL_LEN / 4 {
            builder.try_push_slice(b"xxxx").unwrap();
        }
        assert_eq!(builder.try_push_slice(b"xxxx"), Err(Error::LabelTooLong));
    }

    #[test]
    fn try_push_slice_rejects_long_name() {
        let mut builder = NameBuilder::new();
        for _ in 0..MAX_WIRE_LEN / 4 {
            builder.try_push_slice(b"xxx").unwrap();
            builder.next_label().unwrap();
        }
        assert_eq!(builder.try_push_slice(b"xxx"), Err(Error::NameTooLong));
    }

    #[test]
    fn next_label_rejects_null_non_terminal() {
        let mut builder = NameBuilder::new();
        assert_eq!(builder.next_label(), Err(Error::NullNonTerminal));
    }

    #[test]
    fn next_label_rejects_long_name() {
        let mut builder = NameBuilder::new();
        for _ in 0..MAX_N_LABELS - 2 {
            builder.try_push(b'x').unwrap();
            builder.next_label().unwrap();
        }

        // We now have three octets remaining (space for one label of
        // one character and the null label). So if we add a label of
        // length two, we won't be able to start a new label (no space
        // for its length octet).
        builder.try_push_slice(b"xx").unwrap();
        assert_eq!(builder.next_label(), Err(Error::NameTooLong));
    }
}
