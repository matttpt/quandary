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

//! Implementation of data structures related to domain names.

use std::alloc::{self, Layout};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FusedIterator;
use std::ops::{Index, IndexMut};
use std::ptr;
use std::str::FromStr;

use arrayvec::ArrayVec;

mod builder;
mod error;
mod label;
mod lowercase;
mod wire;
pub use builder::NameBuilder;
pub use error::Error;
pub use label::{Label, LabelBuf};
pub use lowercase::LowercaseName;

/// The maximum number of labels in a domain name.
const MAX_N_LABELS: usize = 128;

/// The maximum length of the uncompressed on-the-wire representation of
/// a domain name.
const MAX_WIRE_LEN: usize = 255;

/// The maximum length of a label in a domain name (not including the
/// octet that provides the length).
const MAX_LABEL_LEN: usize = 63;

////////////////////////////////////////////////////////////////////////
// NAME STRUCTURE                                                     //
////////////////////////////////////////////////////////////////////////

/// A structure to represent a domain name.
///
/// This is a dynamically sized type, generally used through the `&Name`
/// and `Box<Name>` types.
///
/// Boxed `Names` can be constructed in several ways:
///
/// * through the [`FromStr`] implementation;
/// * through a [`NameBuilder`];
/// * from uncompressed on-the-wire names through
///   [`Name::try_from_uncompressed`] and
///   [`Name::try_from_uncompressed_all`]; and
/// * from compressed on-the-wire names through
///   [`Name::try_from_compressed`].
///
/// Internally, a `Name` is represented by the following fields, in
/// order:
///
/// * One octet, `n_labels`, provides the number of labels in the name.
/// * An array of `n_labels` octets provides the offset of each label
///   in the on-the-wire representation of the name, as defined in
///   [RFC 1035 § 3.1].
/// * The on-the-wire representation of the name mentioned above.
///
/// The `Name` structure is defined in Rust includes the `n_labels`
/// field, since it has fixed size, but the label offsets and
/// on-the-wire representation do not have fixed size. In Rust, only the
/// final field of a structure may be unsized, so these are combined
/// into a single unsized field called `data`. The private
/// `label_offsets` method provides access to the label-offset portion
/// for the implementation, and the public [`Name::wire_repr`] method
/// provides access to the wire-representation portion.
///
/// The internal representation used here follows that used by the [NSD]
/// authoritative nameserver.
///
/// The reason for using a finicky custom DST (especially when, as of
/// 2021, Rust support for them is minimal and making it work is hacky)
/// is to promote data locality. Domain names appear very frequently
/// in DNS processing. Thus, it seems wise to avoid pointer indirection
/// for the dynamically sized label-offset and wire-representation
/// buffers. With this model, short domain names (a common occurrence)
/// may often reside within a single cache line!
///
/// The [`slice_dst`] crate was a very helpful reference for this
/// technique!
///
/// [NSD]: https://www.nlnetlabs.nl/projects/nsd/about/
/// [RFC 1035 § 3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
/// [`slice_dst`]: https://docs.rs/slice-dst/latest/slice_dst/
#[repr(C)]
pub struct Name {
    n_labels: u8,
    data: [u8],
}

/// Private helpers to access unsized fields.
impl Name {
    /// Returns the offset of label `n` in the `Name`'s on-the-wire
    /// representation.
    fn label_offset(&self, n: usize) -> usize {
        self.label_offsets()[n] as usize
    }

    /// Returns the offsets of the labels in the `Name`'s on-the-wire
    /// representation.
    fn label_offsets(&self) -> &[u8] {
        &self.data[0..self.len()]
    }
}

/// Private allocation/initialization helpers for use within this module.
impl Name {
    /// Converts a pointer to a buffer in which a name has been
    /// initialized and size information into a const pointer to a
    /// `Name`. Since `Name` is a dynamically sized type, this will be a
    /// fat pointer that includes the size information for the `Name`.
    ///
    /// # Safety
    ///
    /// This operation is not unsafe in itself, but if you want to
    /// actually _use_ the returned pointer/convert it to a reference,
    /// you need to make sure that
    ///
    /// * the buffer has been initialized to a valid `Name` value;
    /// * the memory region lies within a single allocation;
    /// * `n_labels` and `wire_len` are correct; and
    /// * the `Name` object must be no larger than [`isize::MAX`]
    ///   (which will be satisfied if the first condition is met).
    /// * the data is not mutated during the lifetime of the created
    ///   reference.
    fn make_fat_pointer(octets: *const u8, n_labels: usize, wire_len: usize) -> *const Name {
        // NOTE: if/when std::ptr::from_raw_parts becomes available, use
        // it instead. This is how the slice-dst crate works, and I'm
        // not aware of a better way of doing this given Rust's current
        // lack of support for custom DSTs, but this is uncomfortably
        // hacky and, I think, relies on the implementation details.
        ptr::slice_from_raw_parts(octets, n_labels + wire_len) as *const Name
    }

    /// The mutable variant of [`Name::make_fat_pointer`].
    ///
    /// # Safety
    ///
    /// The safety points made for [`Name::make_fat_pointer`] apply with
    /// one difference. It is not enough to ensure that the data is not
    /// mutated during the lifetime of the created reference. One must
    /// ensure that there are no accesses whatsoever (reads or writes)
    /// through other pointers not derived from the one returned during
    /// lifetime of the created reference.
    fn make_fat_pointer_mut(octets: *mut u8, n_labels: usize, wire_len: usize) -> *mut Name {
        // NOTE: if/when std::ptr::from_raw_parts becomes available, use
        // it. See the note in Name::make_fat_pointer.
        ptr::slice_from_raw_parts_mut(octets, n_labels + wire_len) as *mut Name
    }

    /// Initializes a new `Name` structure at the given allocation.
    ///
    /// This will fill in the `n_labels` field based on the number of
    /// label offsets provided. The `label_offsets` slice gives the
    /// index of the starting octet of each label in the domain name's
    /// on-the-wire representation. The slices given in `slices`, when
    /// concatenated, provide the on-the-wire representation of the
    /// name being constructed.
    ///
    /// # Safety
    ///
    /// The caller must ensure that
    ///
    /// * the provided memory region is in fact a single allocation;
    /// * the allocation is valid for writes for the proper size (use
    ///   [`Name::size_required_for`] for this);
    /// * the `slices` provide a valid domain name in the on-the-wire
    ///   representation, and `label_offsets` provides the offsets of
    ///   the labels correctly; and
    /// * none of the slices overlaps the allocation, since
    ///   [`ptr::copy_nonoverlapping`] is used under the hood.
    unsafe fn initialize_into(allocation: *mut u8, label_offsets: &[u8], slices: &[&[u8]]) {
        let n_labels = label_offsets.len();
        allocation.write(n_labels as u8);
        ptr::copy_nonoverlapping(
            label_offsets as *const [u8] as *const u8,
            allocation.add(1),
            n_labels,
        );
        let mut index = 1 + n_labels;
        for slice in slices {
            // The call to ptr::add is safe:
            //
            // * If label_offsets and slices provide a valid domain
            //   name, as our safety preconditions require, then index
            //   does not overflow an isize.
            // * The caller promised that allocation is, in fact, a
            //   single allocated object.
            //
            // The call to ptr::copy_nonoverlapping is safe, since the
            // caller promised that the allocation is valid for the
            // writes we make and that none of the slices overlaps the
            // allocation.
            ptr::copy_nonoverlapping(
                *slice as *const [u8] as *const u8,
                allocation.add(index),
                slice.len(),
            );
            index += slice.len();
        }
    }

    /// Returns the size required for a `Name` structure representing
    /// a domain name with `n_labels` labels and whose on-the-wire
    /// representation is `wire_len` octets long.
    const fn size_required_for(n_labels: usize, wire_len: usize) -> usize {
        1 + n_labels + wire_len
    }
}

////////////////////////////////////////////////////////////////////////
// NAME PUBLIC API                                                    //
////////////////////////////////////////////////////////////////////////

#[allow(clippy::len_without_is_empty)] // A domain name is never empty!
impl Name {
    /// Returns whether this `Name` is equal to or a subdomain of
    /// `other`.
    pub fn eq_or_subdomain_of(&self, other: &Name) -> bool {
        self.len() >= other.len()
            && self
                .labels()
                .rev()
                .zip(other.labels().rev())
                .all(|(a, b)| a == b)
    }

    /// Returns whether the `Name` is the DNS root `.`.
    pub fn is_root(&self) -> bool {
        self.n_labels == 1
    }

    /// Returns whether the `Name` is a wildcard domain name (i.e.,
    /// whether its first label is `*`).
    pub fn is_wildcard(&self) -> bool {
        self[0].is_asterisk()
    }

    /// Returns an iterator over labels in this `Name`.
    pub fn labels(&self) -> Labels {
        Labels::new(self)
    }

    /// Returns the number of labels in this `Name`.
    pub fn len(&self) -> usize {
        self.n_labels as usize
    }

    /// Makes all ASCII letters in this `Name` lowercase.
    ///
    /// This is provided with [RFC 4034 § 6.2] (DNSSEC canonical RR
    /// form) in mind. See also [`LowercaseName`].
    ///
    /// [RFC 4034 § 6.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
    pub fn make_ascii_lowercase(&mut self) {
        // NOTE: we just iterate manually, since writing a LabelsMut
        // iterator is tricky due to lifetime issues.
        for i in 0..self.len() {
            self[i].octets_mut().make_ascii_lowercase();
        }
    }

    /// Returns a reference to a `Name` representing the DNS root, `.`.
    pub fn root() -> &'static Name {
        static ROOT_NAME_REPR: [u8; 3] = [1, 0, 0];
        unsafe {
            // SAFETY: this is a valid Name value; the data is within a
            // single object/allocation; the number of labels and wire
            // length are indeed both 1; and the data will not ever be
            // mutated.
            &*Name::make_fat_pointer(&ROOT_NAME_REPR as *const [u8] as *const u8, 1, 1)
        }
    }

    /// Tries to skip a compressed name at the beginning of `octets`.
    /// This continues until the end of the name or the first pointer
    /// label, whichever comes first, and returns the number of octets
    /// read.
    ///
    /// This performs validation only on the portion of the name read.
    /// Furthermore, when this terminates at a pointer, it does *not*
    /// check whether the pointer itself is valid (i.e., points
    /// backward).
    pub fn skip_compressed(octets: &[u8]) -> Result<usize, Error> {
        wire::skip_compressed_name(octets)
    }

    /// Returns the superdomain obtained by skipping the first `skip`
    /// labels of the `Name`, or `None` if there aren't enough labels.
    pub fn superdomain(&self, skip: usize) -> Option<Box<Name>> {
        if skip < self.len() {
            let start = self.label_offset(skip);
            let slice = &self.wire_repr()[start..];
            let original_label_offsets = &self.label_offsets()[skip..];
            let new_label_offsets: ArrayVec<u8, MAX_N_LABELS> = original_label_offsets
                .iter()
                .map(|offset| offset - original_label_offsets[0])
                .collect();
            unsafe {
                // SAFETY: extracting a superdomain (and adjusting the
                // label offsets) as we have done here yields a valid
                // domain name (and the correct corresponding label
                // offsets).
                Some(new_boxed_name(slice.len(), &new_label_offsets, &[slice]))
            }
        } else {
            None
        }
    }

    /// Tries to parse a compressed name present at index `start` of the
    /// provided buffer. Pointers are followed; indices given in
    /// pointers are treated as equivalent to indices in `octets` (so
    /// generally one will pass an entire DNS message in `octets`). Two
    /// things are returned on success:
    ///
    /// * a new boxed `Name`; and
    /// * the number of contiguous octets read at `start`. Equivalently,
    ///   the number of octets to skip after `start` to read the next
    ///   field when parsing a DNS message. For example, if the name has
    ///   no pointers, this value will be the length (in octets) of the
    ///   uncompressed on-the-wire representation of the name. If, on the
    ///   other hand, a pointer label is present at `start`, this value
    ///   will be 2.
    pub fn try_from_compressed(octets: &[u8], start: usize) -> Result<(Box<Self>, usize), Error> {
        wire::parse_compressed_name(octets, start)
    }

    /// Tries to parse an uncompressed name present at the start of the
    /// provided buffer. The name need not occupy the entire buffer;
    /// extra data is ignored. If the name is valid, a new boxed `Name`
    /// is returned along with the length of the name in octets.
    pub fn try_from_uncompressed(octets: &[u8]) -> Result<(Box<Self>, usize), Error> {
        wire::parse_uncompressed_name(octets, false)
    }

    /// Like [`Name::try_from_uncompressed`], but in addition fails if
    /// there is extra data in the buffer after the name (and does not
    /// return the length of the name on success, since it is equal to
    /// the length of the buffer).
    pub fn try_from_uncompressed_all(octets: &[u8]) -> Result<Box<Self>, Error> {
        wire::parse_uncompressed_name(octets, true).map(|(name, _)| name)
    }

    /// Validates an uncompresed name present at the start of the
    /// provided buffer; this is [`Name::try_from_uncompressed`], except
    /// it does not allocate a new boxed `Name`. The name need not occupy
    /// the entire buffer; extra data is ignored. If it is valid, the
    /// length of the name in octets is returned.
    pub fn validate_uncompressed(octets: &[u8]) -> Result<usize, Error> {
        wire::validate_uncompressed_name(octets, false)
    }

    /// Like [`Name::validate_uncompressed`], but in addition fails if
    /// there is extra data in the buffer after the name (and does not
    /// return the length of the name on success, since it is equal to
    /// the length of the buffer).
    pub fn validate_uncompressed_all(octets: &[u8]) -> Result<(), Error> {
        wire::validate_uncompressed_name(octets, true).and(Ok(()))
    }

    /// Returns the (uncompressed) on-the-wire representation of the
    /// `Name`.
    pub fn wire_repr(&self) -> &[u8] {
        &self.data[self.len()..]
    }

    /// The mutable version of [`Name::wire_repr`] for internal use. All
    /// (internal) users must be sure to keep the label count and label
    /// offsets in sync with any modifications made.
    pub fn wire_repr_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.data[len..]
    }

    /// Returns the (uncompressed) on-the-wire representation of the
    /// first `n` labels of the `Name`. This will panic if
    /// `n > self.len()`.
    pub fn wire_repr_to(&self, n: usize) -> &[u8] {
        if n == self.len() {
            self.wire_repr()
        } else {
            &self.wire_repr()[0..self.label_offset(n)]
        }
    }

    /// Returns the (uncompressed) on-the-wire representation of the
    /// `Name` starting with the `n`-th label. If `n == self.len()`,
    /// this returns an empty slice; if `n > self.len()`, this panics.
    pub fn wire_repr_from(&self, n: usize) -> &[u8] {
        if n == self.len() {
            &[]
        } else {
            &self.wire_repr()[self.label_offset(n)..]
        }
    }
}

impl Index<usize> for Name {
    type Output = Label;

    fn index(&self, index: usize) -> &Self::Output {
        let offset = self.label_offset(index);
        let len = self.wire_repr()[offset] as usize;
        let start = offset + 1;
        let end = start + len;
        Label::from_unchecked(&self.wire_repr()[start..end])
    }
}

impl IndexMut<usize> for Name {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let offset = self.label_offset(index);
        let len = self.wire_repr()[offset] as usize;
        let start = offset + 1;
        let end = start + len;
        Label::from_unchecked_mut(&mut self.wire_repr_mut()[start..end])
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.len() <= 1 {
            f.write_str(".")
        } else {
            // NOTE: the unwrap() is okay, since we never construct
            // Names with no labels.
            let mut labels = self.labels();
            labels.next().unwrap().fmt(f)?;
            for label in labels {
                write!(f, ".{}", label)?;
            }
            Ok(())
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.labels().zip(other.labels()).all(|(a, b)| a == b)
    }
}

impl Eq for Name {}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The [`Ord`] implementation for `Name` employs DNSSEC's canonical
/// ordering of domain names. Per [RFC 4034 § 6.1], `Name`s are ordered
/// as strings of labels read from right to left.
///
/// [RFC 4034 § 6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        self.labels()
            .rev()
            .zip(other.labels().rev())
            .find_map(|(a, b)| Some(a.cmp(b)).filter(|ordering| ordering.is_ne()))
            .unwrap_or_else(|| self.len().cmp(&other.len()))
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for label in self.labels() {
            label.hash(state);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// ITERATION OVER A NAME'S LABELS                                     //
////////////////////////////////////////////////////////////////////////

/// An iterator over the [`Label`]s in a [`Name`].
///
/// To use this iterator, construct one from a [`Name`] using
/// [`Name::labels`].
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    name: &'a Name,
    front: usize,
    back: usize,
}

impl Labels<'_> {
    fn new(name: &Name) -> Labels {
        Labels {
            name,
            front: 0,
            back: name.len(),
        }
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front < self.back {
            let this_one = self.front;
            self.front += 1;
            Some(&self.name[this_one])
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.back - self.front;
        (len, Some(len))
    }
}

impl DoubleEndedIterator for Labels<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.back > self.front {
            self.back -= 1;
            Some(&self.name[self.back])
        } else {
            None
        }
    }
}

impl ExactSizeIterator for Labels<'_> {}

impl FusedIterator for Labels<'_> {}

////////////////////////////////////////////////////////////////////////
// ALLOCATION AND CLONING OF BOXED NAMES                              //
////////////////////////////////////////////////////////////////////////

/// Allocates and initializes a `Box<Name>`. `wire_len` gives the length
/// (in octets) of the on-the-wire representation of the name.
/// `label_offsets` provides the index of the start of each label in the
/// on-the-wire representation, and the slices in `slices`, when
/// concatenated, provide the on-the-wire representation itself.
///
/// # Safety
///
/// The caller must ensure that:
///
/// * the slices of `slices`, when concatenated, give a valid
///   on-the-wire representation of a domain name, and
/// * `wire_len` and `label_offsets` correctly describe that domain
///   name.
unsafe fn new_boxed_name(wire_len: usize, label_offsets: &[u8], slices: &[&[u8]]) -> Box<Name> {
    // SAFETY:
    // * from_size_align_unchecked: alignment is nonzero and is 2^0.
    //   Since the alignment is 1, we don't need to worry about
    //   overflowing usize::MAX when rounding size up to the nearest
    //   multiple of the alignment.
    // * alloc: the layout has nonzero size (see the implementation of
    //   size_required_for above).
    // * initialize_into: the memory region is one allocation and should
    //   not overlap with any of the slices, since it's a new
    //   allocation. Our caller has promised that label_offsets and
    //   slices give a valid domain name.
    // * from_raw: we know the memory layout of a Name (that's why we
    //   make it repr(C)) and promise that we have computed it properly
    //   here. We also only call from_raw with name_ptr once, so no
    //   double-freeing will occur.
    let n_labels = label_offsets.len();
    let size = Name::size_required_for(n_labels, wire_len);
    let layout = Layout::from_size_align_unchecked(size, 1);
    let allocation = alloc::alloc(layout);
    Name::initialize_into(allocation, label_offsets, slices);
    let name_ptr = Name::make_fat_pointer_mut(allocation, n_labels, wire_len);
    Box::from_raw(name_ptr)
}

impl ToOwned for Name {
    type Owned = Box<Name>;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            // SAFETY: this module guarantees that the Names it creates
            // represent valid domain names, so we're giving
            // new_boxed_name valid arguments.
            new_boxed_name(
                self.wire_repr().len(),
                self.label_offsets(),
                &[self.wire_repr()],
            )
        }
    }
}

impl Clone for Box<Name> {
    fn clone(&self) -> Self {
        self.as_ref().to_owned()
    }
}

////////////////////////////////////////////////////////////////////////
// PARSING OF NAMES FROM RUST STRINGS                                 //
////////////////////////////////////////////////////////////////////////

/// Allows for conversion of a Rust [`str`] into a boxed [`Name`]. The
/// passed string must be strictly ASCII. Escape sequences as defined by
/// [RFC 4343 § 2.1] are supported.
///
/// [RFC 4343 § 2.1]: https://datatracker.ietf.org/doc/html/rfc4343#section-2.1
impl FromStr for Box<Name> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(Error::StrEmpty);
        } else if s == "." {
            return Ok(Name::root().to_owned());
        }

        let mut remaining_octets: &[u8] = s.as_ref();
        let mut builder = NameBuilder::new();

        // NOTE: to check that the string is ASCII, it suffices to check
        // that each octet is ASCII as we go. This is because all
        // multi-byte characters start with an octet that is not ASCII.
        while let Some(&octet) = remaining_octets.first() {
            if octet == b'\\' {
                let (value, consumed) = parse_escape(&remaining_octets[1..])?;
                builder.try_push(value)?;
                remaining_octets = &remaining_octets[consumed + 1..];
            } else if octet == b'.' {
                builder.next_label()?;
                remaining_octets = &remaining_octets[1..];
            } else if !octet.is_ascii() {
                return Err(Error::StrNotAscii);
            } else {
                builder.try_push(octet)?;
                remaining_octets = &remaining_octets[1..];
            }
        }
        builder.finish()
    }
}

/// Parses an escape sequence. We expect `remaining_octets` to start
/// with the octet immediately *after* the backslash that introduces the
/// escape sequence.
fn parse_escape(remaining_octets: &[u8]) -> Result<(u8, usize), Error> {
    if remaining_octets.is_empty() {
        Err(Error::InvalidEscape)
    } else if remaining_octets[0].is_ascii_digit() {
        if remaining_octets.len() < 3
            || !remaining_octets[1].is_ascii_digit()
            || !remaining_octets[2].is_ascii_digit()
        {
            Err(Error::InvalidEscape)
        } else {
            let hundreds = (remaining_octets[0] - b'0') as usize;
            let tens = (remaining_octets[1] - b'0') as usize;
            let ones = (remaining_octets[2] - b'0') as usize;
            let value = 100 * hundreds + 10 * tens + ones;
            if value > 255 {
                Err(Error::InvalidEscape)
            } else {
                Ok((value as u8, 3))
            }
        }
    } else {
        Ok((remaining_octets[0], 1))
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_root() {
        assert!(Name::root().is_root());
    }

    #[test]
    fn root_has_expected_characteristics() {
        let root = Name::root();
        assert_eq!(root.len(), 1);
        assert_eq!(root.label_offsets(), &[0]);
        assert_eq!(root.wire_repr(), &[0]);
    }

    #[test]
    fn is_wildcard_works() {
        let wildcard: Box<Name> = "*.quandary.test.".parse().unwrap();
        let not_a_wildcard: Box<Name> = "quandary.test.".parse().unwrap();
        let double_asterisk: Box<Name> = "*.*.quandary.test.".parse().unwrap();
        let inner_asterisk: Box<Name> = "x.*.quandary.test.".parse().unwrap();
        assert!(wildcard.is_wildcard());
        assert!(!not_a_wildcard.is_wildcard());
        assert!(double_asterisk.is_wildcard());
        assert!(!inner_asterisk.is_wildcard());
    }

    #[test]
    fn superdomain_works() {
        let subdomain: Box<Name> = "subdomain.example.test.".parse().unwrap();
        let domain: Box<Name> = "example.test.".parse().unwrap();
        let tld: Box<Name> = "test.".parse().unwrap();
        assert_eq!(subdomain.superdomain(0).as_ref(), Some(&subdomain));
        assert_eq!(subdomain.superdomain(1), Some(domain));
        assert_eq!(subdomain.superdomain(2), Some(tld));
        assert_eq!(subdomain.superdomain(3).as_deref(), Some(Name::root()));
        assert_eq!(subdomain.superdomain(4), None);
    }

    #[test]
    fn labels_iterator_works() {
        let name: Box<Name> = "a.b.c.d.example.test.".parse().unwrap();
        let mut labels = name.labels();
        assert_eq!(labels.next(), Some(b"a".into()));
        assert_eq!(labels.next(), Some(b"b".into()));
        assert_eq!(labels.next(), Some(b"c".into()));
        assert_eq!(labels.next(), Some(b"d".into()));
        assert_eq!(labels.next(), Some(b"example".into()));
        assert_eq!(labels.next(), Some(b"test".into()));
        assert_eq!(labels.next(), Some(Label::null()));
        assert_eq!(labels.next(), None);
    }

    #[test]
    fn eq_or_subdomain_of_works() {
        let subdomain: Box<Name> = "subdomain.example.test.".parse().unwrap();
        let domain: Box<Name> = "example.test.".parse().unwrap();
        let tld: Box<Name> = "test.".parse().unwrap();
        let root = Name::root();
        assert!(subdomain.eq_or_subdomain_of(&subdomain));
        assert!(subdomain.eq_or_subdomain_of(&domain));
        assert!(subdomain.eq_or_subdomain_of(&tld));
        assert!(subdomain.eq_or_subdomain_of(root));
        assert!(!domain.eq_or_subdomain_of(&subdomain));
        assert!(domain.eq_or_subdomain_of(&domain));
        assert!(domain.eq_or_subdomain_of(&tld));
        assert!(domain.eq_or_subdomain_of(root));
        assert!(!tld.eq_or_subdomain_of(&subdomain));
        assert!(!tld.eq_or_subdomain_of(&domain));
        assert!(tld.eq_or_subdomain_of(&tld));
        assert!(tld.eq_or_subdomain_of(root));
        assert!(!root.eq_or_subdomain_of(&subdomain));
        assert!(!root.eq_or_subdomain_of(&domain));
        assert!(!root.eq_or_subdomain_of(&tld));
        assert!(root.eq_or_subdomain_of(root));

        let other_test: Box<Name> = "other.test.".parse().unwrap();
        let example_invalid: Box<Name> = "example.com.".parse().unwrap();
        assert!(!domain.eq_or_subdomain_of(&other_test));
        assert!(!other_test.eq_or_subdomain_of(&domain));
        assert!(!domain.eq_or_subdomain_of(&example_invalid));
        assert!(!example_invalid.eq_or_subdomain_of(&domain));
    }

    #[test]
    fn wire_repr_from_works() {
        let name: Box<Name> = "a.bb.ccc.".parse().unwrap();
        assert_eq!(name.wire_repr_from(0), b"\x01a\x02bb\x03ccc\x00");
        assert_eq!(name.wire_repr_from(1), b"\x02bb\x03ccc\x00");
        assert_eq!(name.wire_repr_from(2), b"\x03ccc\x00");
        assert_eq!(name.wire_repr_from(3), b"\x00");
        assert_eq!(name.wire_repr_from(4), b"");
    }

    #[test]
    #[should_panic(expected = "index out of bounds: the len is 4 but the index is 5")]
    fn wire_repr_from_rejects_large_index() {
        "a.bb.ccc.".parse::<Box<Name>>().unwrap().wire_repr_from(5);
    }

    #[test]
    fn wire_repr_to_works() {
        let name: Box<Name> = "a.bb.ccc.".parse().unwrap();
        assert_eq!(name.wire_repr_to(0), b"");
        assert_eq!(name.wire_repr_to(1), b"\x01a");
        assert_eq!(name.wire_repr_to(2), b"\x01a\x02bb");
        assert_eq!(name.wire_repr_to(3), b"\x01a\x02bb\x03ccc");
        assert_eq!(name.wire_repr_to(4), b"\x01a\x02bb\x03ccc\x00");
    }

    #[test]
    #[should_panic(expected = "index out of bounds: the len is 4 but the index is 5")]
    fn wire_repr_to_rejects_large_index() {
        "a.bb.ccc.".parse::<Box<Name>>().unwrap().wire_repr_to(5);
    }

    #[test]
    fn ord_works() {
        // This ordered list is from RFC 4034 § 6.1, which defines the
        // canonical ordering of domain names.
        let names: Vec<Box<Name>> = [
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "\\001.z.example.",
            "*.z.example.",
            "\\200.z.example.",
        ]
        .into_iter()
        .map(|n| n.parse().unwrap())
        .collect();

        for (i, ni) in names.iter().enumerate() {
            for (j, nj) in names.iter().enumerate() {
                assert_eq!(i.cmp(&j), ni.cmp(nj));
            }
        }
    }

    #[test]
    fn fromstr_works() {
        let name: Box<Name> = "example.test.".parse().unwrap();
        assert_eq!(name.wire_repr(), b"\x07example\x04test\x00");
    }

    #[test]
    fn fromstr_works_for_root() {
        let name: Box<Name> = ".".parse().unwrap();
        assert_eq!(name.as_ref(), Name::root());
    }

    #[test]
    fn fromstr_rejects_empty() {
        assert_eq!("".parse::<Box<Name>>(), Err(Error::StrEmpty));
    }

    #[test]
    fn fromstr_rejects_non_ascii() {
        assert_eq!("✈.aero.".parse::<Box<Name>>(), Err(Error::StrNotAscii));
    }

    #[test]
    fn fromstr_rejects_non_fqdn() {
        assert_eq!("non.fqdn".parse::<Box<Name>>(), Err(Error::NonNullTerminal));
    }

    #[test]
    fn fromstr_rejects_long_label() {
        assert_eq!(
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx."
                .parse::<Box<Name>>(),
            Err(Error::LabelTooLong)
        );
    }

    #[test]
    fn fromstr_rejects_long_name() {
        assert_eq!(
            "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.\
             x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.\
             x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.\
             x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x."
                .parse::<Box<Name>>(),
            Err(Error::NameTooLong)
        );
    }

    #[test]
    fn fromstr_rejects_null_non_terminal() {
        assert_eq!("a.b..c.".parse::<Box<Name>>(), Err(Error::NullNonTerminal));
    }

    #[test]
    fn fromstr_escaping_works() {
        let escaped: Box<Name> = "\\000.\\\\\\..".parse().unwrap();
        assert_eq!(escaped.wire_repr(), b"\x01\x00\x02\\.\x00");
    }

    #[test]
    fn fromstr_rejects_invalid_escapes() {
        assert_eq!("\\00".parse::<Box<Name>>(), Err(Error::InvalidEscape));
        assert_eq!("\\00x.".parse::<Box<Name>>(), Err(Error::InvalidEscape));
        assert_eq!("\\256.".parse::<Box<Name>>(), Err(Error::InvalidEscape));
    }

    #[test]
    fn make_ascii_lowercase_works() {
        let mut name: Box<Name> = "UPPERCASE.Domain.Test.".parse().unwrap();
        name.make_ascii_lowercase();
        assert_eq!(name.wire_repr(), b"\x09uppercase\x06domain\x04test\x00");
    }
}
