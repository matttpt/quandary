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

//! Implementation of types relating to DNS questions.

use std::fmt;
use std::str::FromStr;

use crate::class::Class;
use crate::name::Name;
use crate::rr::Type;
use crate::util::Caseless;

////////////////////////////////////////////////////////////////////////
// QUESTIONS                                                          //
////////////////////////////////////////////////////////////////////////

/// The question of a DNS query.
///
/// Defined in [RFC 1035 § 4.1.2], a DNS question includes
///
/// * the QNAME, which is the domain name whose records are being
///   queried;
/// * the [QTYPE](Qtype), which specifies what types of records are
///   desired; and
/// * the [QCLASS](Qclass), which specifies which DNS class(es) to search.
///
/// While the original specification does not rule out having multiple
/// questions per message, in practice only one question per message is
/// used.
///
/// [RFC 1035 § 4.1.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Question {
    pub qname: Box<Name>,
    pub qtype: Qtype,
    pub qclass: Qclass,
}

////////////////////////////////////////////////////////////////////////
// QTYPES                                                             //
////////////////////////////////////////////////////////////////////////

/// The QTYPE of a DNS [question](Question).
///
/// The QTYPE determines what type of DNS records are desired. QTYPE
/// values include data TYPEs (see [`Type`]), but may also include
/// other values that often indicate that a range of TYPEs are desired
/// (e.g. [MAILB](Qtype::MAILB) and [*](Qtype::ANY)), or ask for zone
/// transfers (e.g. [AXFR](Qtype::AXFR)).
///
/// A QTYPE is represented on the wire as an unsigned 16-bit integer.
/// Hence this is basically a wrapper around [`u16`] with nice
/// [`Debug`](fmt::Debug), [`Display`](fmt::Display), and [`FromStr`]
/// implementations. In addition, constants for common QTYPEs not
/// covered by [`Type`] are provided.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct Qtype(u16);

impl Qtype {
    // RFC 1995
    pub const IXFR: Self = Self(251);

    // RFC 1035
    pub const AXFR: Self = Self(252);
    pub const MAILB: Self = Self(253);
    pub const MAILA: Self = Self(254);
    pub const ANY: Self = Self(255);
}

impl From<u16> for Qtype {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<Qtype> for u16 {
    fn from(qtype: Qtype) -> Self {
        qtype.0
    }
}

impl From<Type> for Qtype {
    fn from(rr_type: Type) -> Self {
        Self(rr_type.into())
    }
}

impl fmt::Display for Qtype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::IXFR => f.write_str("IXFR"),
            Self::AXFR => f.write_str("AXFR"),
            Self::MAILB => f.write_str("MAILB"),
            Self::MAILA => f.write_str("MAILA"),
            Self::ANY => f.write_str("*"),
            _ => Type::from(*self).fmt(f),
        }
    }
}

impl fmt::Debug for Qtype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for Qtype {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match Caseless(text) {
            Caseless("IXFR") => Ok(Self::IXFR),
            Caseless("AXFR") => Ok(Self::AXFR),
            Caseless("MAILB") => Ok(Self::MAILB),
            Caseless("MAILA") => Ok(Self::MAILA),
            Caseless("ANY") => Ok(Self::ANY),
            Caseless("*") => Ok(Self::ANY),
            _ => Type::from_str(text).map(Into::into),
        }
    }
}

////////////////////////////////////////////////////////////////////////
// QCLASSES                                                           //
////////////////////////////////////////////////////////////////////////

/// The QCLASS of a DNS [question](Question).
///
/// The QCLASS determines which DNS class(es) to search for records.
/// This may be a defined DNS [CLASS]([`Class`]), or it may another
/// value such as [*](`Qclass::ANY`) that asks for certain groups of
/// CLASSes.
///
/// A QCLASS is represented on the wire as an unsigned 16-bit integer.
/// Hence this is basically a wrapper around [`u16`] with nice
/// [`Debug`](fmt::Debug), [`Display`](fmt::Display), and [`FromStr`]
/// implementations. In addition, constants for common QCLASSes not
/// covered by [`Class`] are provided.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct Qclass(u16);

impl Qclass {
    // RFC 2136
    pub const NONE: Self = Self(254);

    // RFC 1035
    pub const ANY: Self = Self(255);
}

impl From<u16> for Qclass {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<Qclass> for u16 {
    fn from(qclass: Qclass) -> Self {
        qclass.0
    }
}

impl From<Class> for Qclass {
    fn from(class: Class) -> Self {
        Self(class.into())
    }
}

impl fmt::Display for Qclass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::NONE => f.write_str("NONE"),
            Self::ANY => f.write_str("*"),
            _ => Class::from(*self).fmt(f),
        }
    }
}

impl fmt::Debug for Qclass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for Qclass {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match Caseless(text) {
            Caseless("NONE") => Ok(Self::NONE),
            Caseless("ANY") => Ok(Self::ANY),
            Caseless("*") => Ok(Self::ANY),
            _ => Class::from_str(text).map(Into::into),
        }
    }
}
