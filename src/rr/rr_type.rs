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

//! Provides the [`Type`] structure for DNS RR types.

use std::fmt;
use std::str::FromStr;

use crate::message::Qtype;
use crate::util::Caseless;

////////////////////////////////////////////////////////////////////////
// RR TYPES                                                           //
////////////////////////////////////////////////////////////////////////

/// Represents the RR type of a DNS record.
///
/// An RR type is represented on the wire as an unsigned 16-bit integer.
/// Hence this is basically a wrapper around `u16` with nice
/// [`Debug`](fmt::Debug), [`Display`](fmt::Display), and [`FromStr`]
/// implementations for working with the common textual representations
/// of RR types. In addition, constants for common RR types (e.g.
/// [`Type::A`] are provided.
#[derive(Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Type(u16);

impl Type {
    pub const A: Type = Type(1);
    pub const NS: Type = Type(2);
    pub const MD: Type = Type(3);
    pub const MF: Type = Type(4);
    pub const CNAME: Type = Type(5);
    pub const SOA: Type = Type(6);
    pub const MB: Type = Type(7);
    pub const MG: Type = Type(8);
    pub const MR: Type = Type(9);
    pub const NULL: Type = Type(10);
    pub const WKS: Type = Type(11);
    pub const PTR: Type = Type(12);
    pub const HINFO: Type = Type(13);
    pub const MINFO: Type = Type(14);
    pub const MX: Type = Type(15);
    pub const TXT: Type = Type(16);
    pub const AAAA: Type = Type(28);
    pub const SRV: Type = Type(33);
    pub const OPT: Type = Type(41);
    pub const TSIG: Type = Type(250);
}

impl From<u16> for Type {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<Type> for u16 {
    fn from(rr_type: Type) -> Self {
        rr_type.0
    }
}

impl From<Qtype> for Type {
    fn from(qtype: Qtype) -> Self {
        Self(qtype.into())
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match Caseless(text) {
            Caseless("A") => Ok(Self::A),
            Caseless("NS") => Ok(Self::NS),
            Caseless("MD") => Ok(Self::MD),
            Caseless("MF") => Ok(Self::MF),
            Caseless("CNAME") => Ok(Self::CNAME),
            Caseless("SOA") => Ok(Self::SOA),
            Caseless("MB") => Ok(Self::MB),
            Caseless("MG") => Ok(Self::MG),
            Caseless("MR") => Ok(Self::MR),
            Caseless("NULL") => Ok(Self::NULL),
            Caseless("WKS") => Ok(Self::WKS),
            Caseless("PTR") => Ok(Self::PTR),
            Caseless("HINFO") => Ok(Self::HINFO),
            Caseless("MINFO") => Ok(Self::MINFO),
            Caseless("MX") => Ok(Self::MX),
            Caseless("TXT") => Ok(Self::TXT),
            Caseless("AAAA") => Ok(Self::AAAA),
            Caseless("SRV") => Ok(Self::SRV),
            Caseless("OPT") => Ok(Self::OPT),
            Caseless("TSIG") => Ok(Self::TSIG),
            _ => {
                if text
                    .get(0..4)
                    .map_or(false, |prefix| prefix.eq_ignore_ascii_case("TYPE"))
                {
                    text[4..]
                        .parse::<u16>()
                        .map(Self::from)
                        .or(Err("type value is not a valid unsigned 16-bit integer"))
                } else {
                    Err("unknown type")
                }
            }
        }
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::A => f.write_str("A"),
            Self::NS => f.write_str("NS"),
            Self::MD => f.write_str("MD"),
            Self::MF => f.write_str("MF"),
            Self::CNAME => f.write_str("CNAME"),
            Self::SOA => f.write_str("SOA"),
            Self::MB => f.write_str("MB"),
            Self::MG => f.write_str("MG"),
            Self::MR => f.write_str("MR"),
            Self::NULL => f.write_str("NULL"),
            Self::WKS => f.write_str("WKS"),
            Self::PTR => f.write_str("PTR"),
            Self::HINFO => f.write_str("HINFO"),
            Self::MINFO => f.write_str("MINFO"),
            Self::MX => f.write_str("MX"),
            Self::TXT => f.write_str("TXT"),
            Self::AAAA => f.write_str("AAAA"),
            Self::SRV => f.write_str("SRV"),
            Self::OPT => f.write_str("OPT"),
            Self::TSIG => f.write_str("TSIG"),
            Self(value) => write!(f, "TYPE{value}"), // RFC 3597 § 5
        }
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_displays_according_to_rfc3597() {
        // TYPE65280 is from the private use range, so it should always
        // be unknown.
        let class = Type::from(0xff00);
        assert_eq!(class.to_string(), "TYPE65280");
    }

    #[test]
    fn type_parses_according_to_rfc3597() {
        // Again, TYPE65280 is from the private use range.
        let type_a: Type = "TYPE1".parse().unwrap();
        let type_65280: Type = "TYPE65280".parse().unwrap();
        assert_eq!(type_a, Type::A);
        assert_eq!(u16::from(type_65280), 65280);
    }
}
