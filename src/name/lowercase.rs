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

//! Implementation of the [`LowercaseName`] type.

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use super::{Error, Name};

/// A domain name whose ASCII letters are all lowercase.
///
/// Various parts of the DNS involve domain names in all-lowercase form.
/// DNSSEC canonical RR form (defined by [RFC 4034 § 6.2]) requires all
/// ASCII letters in certain domain names to be lowercase. Likewise TSIG
/// MACs are computed using the key name and algorithm name in the
/// canonical form prescribed by DNSSEC (see [RFC 8945 § 4.3.3]), i.e,
/// all-lowercase form.
///
/// For such applications, the [`LowercaseName`] type provides a wrapper
/// over [`Name`] that is only constructed when the underlying [`Name`]
/// is in all-lowercase form.
///
/// [RFC 4034 § 6.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
/// [RFC 8945 § 4.3.3]: https://datatracker.ietf.org/doc/html/rfc8945#section-4.3.3
#[derive(Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct LowercaseName(Name);

impl From<Box<Name>> for Box<LowercaseName> {
    fn from(mut boxed_name: Box<Name>) -> Self {
        boxed_name.make_ascii_lowercase();
        unsafe { Box::from_raw(Box::into_raw(boxed_name) as *mut LowercaseName) }
    }
}

impl From<Box<LowercaseName>> for Box<Name> {
    fn from(boxed_lowercase_name: Box<LowercaseName>) -> Self {
        unsafe { Box::from_raw(Box::into_raw(boxed_lowercase_name) as *mut Name) }
    }
}

impl ToOwned for LowercaseName {
    type Owned = Box<LowercaseName>;

    fn to_owned(&self) -> Self::Owned {
        let boxed_name = self.0.to_owned();
        unsafe { Box::from_raw(Box::into_raw(boxed_name) as *mut LowercaseName) }
    }
}

impl Clone for Box<LowercaseName> {
    fn clone(&self) -> Self {
        self.deref().to_owned()
    }
}

impl AsRef<Name> for LowercaseName {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

impl AsRef<Name> for Box<LowercaseName> {
    fn as_ref(&self) -> &Name {
        &self.0
    }
}

impl Borrow<Name> for LowercaseName {
    fn borrow(&self) -> &Name {
        &self.0
    }
}

impl Borrow<Name> for Box<LowercaseName> {
    fn borrow(&self) -> &Name {
        &self.0
    }
}

impl Deref for LowercaseName {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Box<LowercaseName> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<Box<Name>>().map(Into::into)
    }
}

impl fmt::Display for LowercaseName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Name;
    use super::LowercaseName;

    #[test]
    fn conversion_makes_lowercase() {
        let name: Box<Name> = "UPPERCASE.Domain.Test.".parse().unwrap();
        let lowercase: Box<LowercaseName> = name.into();
        assert_eq!(
            lowercase.wire_repr(),
            b"\x09uppercase\x06domain\x04test\x00",
        );
    }
}
