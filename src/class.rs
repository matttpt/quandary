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

//! Implementation of the [`Class`] type for DNS classes.

use std::fmt;
use std::str::FromStr;

use crate::message::Qclass;
use crate::util::Caseless;

/// Represents a class in the DNS.
///
/// A class is represented on the wire as an unsigned 16-bit integer, so
/// this is basically a wrapper around [`u16`] with nice
/// [`Debug`](fmt::Debug), [`Display`](fmt::Display), and [`FromStr`]
/// implementations, as well as constants for the defined classes. The
/// only class in common use is [`IN`](Class::IN).
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Class(u16);

impl Class {
    // RFC 1035. We don't include CS because it's no longer listed by
    // the IANA.
    pub const IN: Self = Self(1);
    pub const CH: Self = Self(3);
    pub const HS: Self = Self(4);
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        Class(value)
    }
}

impl From<Class> for u16 {
    fn from(class: Class) -> Self {
        class.0
    }
}

impl From<Qclass> for Class {
    fn from(qclass: Qclass) -> Self {
        Self(qclass.into())
    }
}

impl FromStr for Class {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match Caseless(text) {
            Caseless("IN") => Ok(Self::IN),
            Caseless("CH") => Ok(Self::CH),
            Caseless("HS") => Ok(Self::HS),
            _ => {
                if text
                    .get(0..5)
                    .map_or(false, |prefix| prefix.eq_ignore_ascii_case("CLASS"))
                {
                    text[5..]
                        .parse::<u16>()
                        .map(Self::from)
                        .or(Err("class value is not a valid unsigned 16-bit integer"))
                } else {
                    Err("unknown class")
                }
            }
        }
    }
}

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::IN => write!(f, "IN"),
            Self::CH => write!(f, "CH"),
            Self::HS => write!(f, "HS"),
            Self(value) => write!(f, "CLASS{}", value), // RFC 3597 § 5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Class;

    #[test]
    fn displays_according_to_rfc3597() {
        // CLASS65280 is from the private use range, so it should always
        // be unknown.
        let class = Class::from(0xff00);
        assert_eq!(class.to_string(), "CLASS65280");
    }

    #[test]
    fn parses_according_to_rfc3597() {
        // Again, CLASS65280 is from the private use range.
        let class_in: Class = "CLASS1".parse().unwrap();
        let class_65280: Class = "CLASS65280".parse().unwrap();
        assert_eq!(class_in, Class::IN);
        assert_eq!(u16::from(class_65280), 65280);
    }
}
