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

//! Implementation of the [`Label`] and [`LabelBuf`] types.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use super::{Error, MAX_LABEL_LEN};

////////////////////////////////////////////////////////////////////////
// LABELS                                                             //
////////////////////////////////////////////////////////////////////////

/// The label given to a node in the Domain Name System's tree
/// structure.
///
/// `Label` is essentially a wrapper over `[u8]` that can only be
/// constucted if the slice is a valid DNS label (that is, if it is no
/// more than 63 octets long).
///
/// Note that in accordance with [RFC 1034 § 3.1]:
///
/// * comparisons between `Label`s are case-insensitive assuming ASCII,
///   but
/// * case is preserved in the internal representation.
///
/// `&Label` implements [`TryFrom`] for `&[u8]` and `From` for
/// `&[u8; N]` (where 0 ≤ `N` ≤ 63) for easy construction:
///
/// ```
/// use std::convert::TryFrom;
/// use quandary::name::Label;
///
/// let label1: &Label = b"com".into();
/// let label2 = <&Label>::try_from(&b"org"[..]).unwrap();
/// ```
///
/// [RFC 1034 § 3.1]: https://tools.ietf.org/html/rfc1034#section-3.1
#[repr(transparent)]
pub struct Label {
    octets: [u8],
}

#[allow(clippy::len_without_is_empty)] // Following DNS terminology, we have is_null().
impl Label {
    /// Returns the asterisk label `*`, which has a special meaning in
    /// the DNS lookup process.
    pub fn asterisk() -> &'static Self {
        static ASTERISK_LABEL: &[u8; 1] = b"*";
        Self::from_unchecked(ASTERISK_LABEL)
    }

    /// Wraps up a `&[u8]` as a `Label` without checking its length for
    /// validity. To be used only within the parent module, and only
    /// after performing the length check manually.
    pub(super) fn from_unchecked(octets: &[u8]) -> &Self {
        unsafe { &*(octets as *const [u8] as *const Label) }
    }

    /// Returns whether this `Label` is the asterisk label.
    pub fn is_asterisk(&self) -> bool {
        self == Self::asterisk()
    }

    /// Returns whether this `Label` is the null (zero-length) label.
    pub fn is_null(&self) -> bool {
        self.octets.is_empty()
    }

    /// Returns the number of octets in this `Label`.
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Returns the null (zero-length) `Label`.
    pub fn null() -> &'static Self {
        Self::from_unchecked(&[])
    }

    /// Returns the octets of this `Label`.
    pub fn octets(&self) -> &[u8] {
        &self.octets
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Label {
    type Error = Error;

    fn try_from(octets: &'a [u8]) -> Result<Self, Self::Error> {
        if octets.len() > MAX_LABEL_LEN {
            Err(Error::LabelTooLong)
        } else {
            Ok(Label::from_unchecked(octets))
        }
    }
}

macro_rules! make_label_from_impl_for_n {
    ($n:expr) => {
        impl<'a> From<&'a [u8; $n]> for &'a Label {
            fn from(octets: &'a [u8; $n]) -> Self {
                Label::from_unchecked(octets)
            }
        }
    };
}

macro_rules! make_label_from_impl_for_eight {
    ($n:expr) => {
        make_label_from_impl_for_n!($n);
        make_label_from_impl_for_n!($n + 1);
        make_label_from_impl_for_n!($n + 2);
        make_label_from_impl_for_n!($n + 3);
        make_label_from_impl_for_n!($n + 4);
        make_label_from_impl_for_n!($n + 5);
        make_label_from_impl_for_n!($n + 6);
        make_label_from_impl_for_n!($n + 7);
    };
}

make_label_from_impl_for_eight!(0);
make_label_from_impl_for_eight!(8);
make_label_from_impl_for_eight!(16);
make_label_from_impl_for_eight!(24);
make_label_from_impl_for_eight!(32);
make_label_from_impl_for_eight!(40);
make_label_from_impl_for_eight!(48);
make_label_from_impl_for_eight!(56);

impl ToOwned for Label {
    type Owned = LabelBuf;

    fn to_owned(&self) -> Self::Owned {
        Self::Owned::from_unchecked(self.octets())
    }
}

/// When a `Label` is displayed, periods, backslashes, and octets that
/// are not ASCII graphic characters are escaped in accordance with
/// RFC 1035 § 5.1 and RFC 4343 § 2.1.
/// * Periods are escaped `\.`;
/// * backslashes are escaped `\\`;
/// * all other ASCII graphic characters are not escaped; and
/// * all other octets are escaped `\xyz`, where `xyz` is the
///   three-digit zero-padded decimal representation of the octet.
impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for octet in self.octets() {
            if *octet == b'.' {
                f.write_str("\\.")?;
            } else if *octet == b'\\' {
                f.write_str("\\\\")?;
            } else if octet.is_ascii_graphic() {
                write!(f, "{}", *octet as char)?;
            } else {
                write!(f, "\\{:03}", *octet)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

/// In accordance with RFC 1034 § 3.1 (clarified by RFC 4343),
/// comparison of `Label`s is ASCII-case-insensitive.
impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.octets().eq_ignore_ascii_case(other.octets())
    }
}

impl Eq for Label {}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The [`Ord`] implementation for `Label` employs DNSSEC's canonical
/// ordering of labels. In accordance with [RFC 4034 § 6.1], `Label`s
/// are ordered "as unsigned left-justified octet strings," with the
/// additional stipulation that uppercase ASCII letters are treated as
/// if they were lowercase.
///
/// [RFC 4034 § 6.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.1
impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.octets
            .iter()
            .zip(other.octets.iter())
            .find_map(
                |(a, b)| match a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()) {
                    Ordering::Less => Some(Ordering::Less),
                    Ordering::Greater => Some(Ordering::Greater),
                    Ordering::Equal => None,
                },
            )
            .unwrap_or_else(|| self.octets.len().cmp(&other.octets.len()))
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We have to hash in a case-insensitive manner to match our
        // implementations of [`PartialEq`] and [`Eq`].
        for octet in self.octets().iter().map(|octet| octet.to_ascii_lowercase()) {
            state.write_u8(octet);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// LABEL BUFFERS                                                      //
////////////////////////////////////////////////////////////////////////

/// A fixed-size buffer capable of holding any valid DNS label. It
/// dereferences to a [`Label`].
///
/// The notes about case an internal representation found in the
/// documentation for [`Label`] apply equally here.
///
/// Like [`Label`], `LabelBuf` implements [`TryFrom`] for `&[u8]` and
/// `From` for `&[u8; N]` (where 0 ≤ `N` ≤ 63):
///
/// ```
/// use std::convert::TryFrom;
/// use quandary::name::LabelBuf;
///
/// let labelbuf1 = LabelBuf::from(b"com");
/// let labelbuf2 = LabelBuf::try_from(&b"org"[..]).unwrap();
/// ```
pub struct LabelBuf {
    len: u8,
    data: [u8; MAX_LABEL_LEN],
}

/// Private implementation helpers.
impl LabelBuf {
    /// Constructs a `LabelBuf` from the given octets. The length of the
    /// slice is checked only in an assertion; the caller is expected to
    /// ensure that it is valid.
    fn from_unchecked(octets: &[u8]) -> Self {
        assert!(octets.len() <= MAX_LABEL_LEN);
        let mut buf = LabelBuf {
            len: octets.len() as u8,
            data: [0; MAX_LABEL_LEN],
        };
        buf.data[..octets.len()].copy_from_slice(octets);
        buf
    }
}

impl TryFrom<&[u8]> for LabelBuf {
    type Error = Error;

    fn try_from(octets: &[u8]) -> Result<Self, Self::Error> {
        if octets.len() > MAX_LABEL_LEN {
            Err(Error::LabelTooLong)
        } else {
            Ok(Self::from_unchecked(octets))
        }
    }
}

macro_rules! make_labelbuf_from_impl_for_n {
    ($n:expr) => {
        impl From<&[u8; $n]> for LabelBuf {
            fn from(octets: &[u8; $n]) -> Self {
                Self::from_unchecked(octets)
            }
        }
    };
}

macro_rules! make_labelbuf_from_impl_for_eight {
    ($n:expr) => {
        make_labelbuf_from_impl_for_n!($n);
        make_labelbuf_from_impl_for_n!($n + 1);
        make_labelbuf_from_impl_for_n!($n + 2);
        make_labelbuf_from_impl_for_n!($n + 3);
        make_labelbuf_from_impl_for_n!($n + 4);
        make_labelbuf_from_impl_for_n!($n + 5);
        make_labelbuf_from_impl_for_n!($n + 6);
        make_labelbuf_from_impl_for_n!($n + 7);
    };
}

make_labelbuf_from_impl_for_eight!(0);
make_labelbuf_from_impl_for_eight!(8);
make_labelbuf_from_impl_for_eight!(16);
make_labelbuf_from_impl_for_eight!(24);
make_labelbuf_from_impl_for_eight!(32);
make_labelbuf_from_impl_for_eight!(40);
make_labelbuf_from_impl_for_eight!(48);
make_labelbuf_from_impl_for_eight!(56);

impl Deref for LabelBuf {
    type Target = Label;

    fn deref(&self) -> &Self::Target {
        let len = self.len as usize;
        unsafe { &*(&self.data[..len] as *const [u8] as *const Label) }
    }
}

impl Borrow<Label> for LabelBuf {
    fn borrow(&self) -> &Label {
        self.deref()
    }
}

impl fmt::Display for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.deref())
    }
}

impl fmt::Debug for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self.deref())
    }
}

// For use in HashMaps, Eq and Hash must be the same as for the
// corresponding Label.
impl PartialEq for LabelBuf {
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl Eq for LabelBuf {}

impl PartialOrd for LabelBuf {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.deref().partial_cmp(other.deref())
    }
}

impl Ord for LabelBuf {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}

impl Hash for LabelBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn label_try_from_slice_accepts_ok_lengths() {
        let octets = &[0; MAX_LABEL_LEN];
        for i in 0..=MAX_LABEL_LEN {
            <&Label>::try_from(&octets[0..i]).unwrap();
        }
    }

    #[test]
    fn labelbuf_try_from_slice_accepts_ok_lengths() {
        let octets = &[0; MAX_LABEL_LEN];
        for i in 0..=MAX_LABEL_LEN {
            LabelBuf::try_from(&octets[0..i]).unwrap();
        }
    }

    #[test]
    fn label_try_from_slice_rejects_bad_lengths() {
        assert_eq!(
            <&Label>::try_from(&[0; MAX_LABEL_LEN + 1][..]),
            Err(Error::LabelTooLong)
        );
        assert_eq!(<&Label>::try_from(&[0; 97][..]), Err(Error::LabelTooLong));
    }

    #[test]
    fn labelbuf_try_from_slice_rejects_bad_lengths() {
        assert_eq!(
            LabelBuf::try_from(&[0; MAX_LABEL_LEN + 1][..]),
            Err(Error::LabelTooLong)
        );
        assert_eq!(LabelBuf::try_from(&[0; 97][..]), Err(Error::LabelTooLong));
    }

    #[test]
    fn asterisk_is_asterisk() {
        assert!(Label::asterisk().is_asterisk());
    }

    #[test]
    fn null_is_null() {
        assert!(Label::null().is_null());
    }

    fn eq_and_hash_are_case_insensitive<L>()
    where
        L: fmt::Debug + Eq + Hash + From<&'static [u8; 7]>,
    {
        let uppercase: L = b"EXAMPLE".into();
        let lowercase: L = b"example".into();

        // Ensure that the Eq implementation is case-insensitive.
        assert_eq!(uppercase, lowercase);

        // Ensure that the Hash implementation is case-insensitive.
        let mut hasher = DefaultHasher::new();
        uppercase.hash(&mut hasher);
        let uppercase_hash = hasher.finish();
        let mut hasher = DefaultHasher::new();
        lowercase.hash(&mut hasher);
        let lowercase_hash = hasher.finish();
        assert_eq!(uppercase_hash, lowercase_hash);
    }

    #[test]
    fn label_eq_and_hash_are_case_insensitive() {
        eq_and_hash_are_case_insensitive::<&Label>();
    }

    #[test]
    fn labelbuf_eq_and_hash_are_case_insensitive() {
        eq_and_hash_are_case_insensitive::<LabelBuf>();
    }

    #[test]
    fn labelbuf_hash_matches_label_hash() {
        // The hashes need to match so that LabelBufs can be HashMap
        // keys.
        let labelbuf: LabelBuf = b"label".into();
        let label: &Label = labelbuf.borrow();

        let mut hasher = DefaultHasher::new();
        label.hash(&mut hasher);
        let label_hash = hasher.finish();
        let mut hasher = DefaultHasher::new();
        labelbuf.hash(&mut hasher);
        let labelbuf_hash = hasher.finish();
        assert_eq!(label_hash, labelbuf_hash);
    }

    fn ord_works<L>()
    where
        L: Ord + TryFrom<&'static [u8]>,
        <L as TryFrom<&'static [u8]>>::Error: fmt::Debug,
    {
        let labels = [
            (0, b"exam".as_slice()),
            (1, b"example".as_slice()),
            (1, b"eXaMpLe".as_slice()),
            (2, b"examples".as_slice()),
            (3, b"label".as_slice()),
        ]
        .into_iter()
        .map(|(i, l)| (i, L::try_from(l).unwrap()))
        .collect::<Vec<_>>();

        for (i, li) in labels.iter() {
            for (j, lj) in labels.iter() {
                assert_eq!(i.cmp(j), li.cmp(lj));
            }
        }
    }

    #[test]
    fn label_ord_works() {
        ord_works::<&Label>();
    }

    #[test]
    fn labelbuf_ord_works() {
        ord_works::<LabelBuf>();
    }

    #[test]
    fn label_display_escaping_works() {
        assert_eq!(<&Label>::from(b"\x00\\.a").to_string(), "\\000\\\\\\.a");
    }

    #[test]
    fn labelbuf_display_escaping_works() {
        assert_eq!(LabelBuf::from(b"\x00\\.a").to_string(), "\\000\\\\\\.a");
    }
}
