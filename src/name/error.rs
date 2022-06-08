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

//! Implementation of the [`Error`] type for name-related errors.

use std::fmt;

/// An error type used to report problems constructing label and name
/// types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    /// Extra data was found after the name while parsing.
    ExtraData,

    /// An invalid escape sequence was encountered when parsing a
    /// [`Name`](super::Name) from a [`str`].
    InvalidEscape,

    /// An invalid pointer was encountered while parsing a compressed
    /// name.
    InvalidPointer,

    /// A label was longer than 63 octets.
    LabelTooLong,

    /// The name is too long (longer than 255 octets on the wire).
    NameTooLong,

    /// No labels were provided when constructing a
    /// [`Name`](super::Name).
    NoLabelsProvided,

    /// The last label was not the null label.
    NonNullTerminal,

    /// A null label was found in a non-terminal position.
    NullNonTerminal,

    /// When parsing a [`Name`](super::Name) from a [`str`], the string
    /// was empty.
    StrEmpty,

    /// When parsing a [`Name`](super::Name) from a [`str`], the string
    /// was not strictly ASCII.
    StrNotAscii,

    /// We unexpectedly encountered the end of the message while parsing
    /// the name.
    UnexpectedEom,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::ExtraData => f.write_str("extra data was present"),
            Self::InvalidEscape => f.write_str("invalid escape sequence"),
            Self::InvalidPointer => f.write_str("invalid pointer"),
            Self::LabelTooLong => f.write_str("label is longer than 64 bytes on the wire"),
            Self::NameTooLong => f.write_str("name is longer than 255 bytes on the wire"),
            Self::NoLabelsProvided => f.write_str("no labels provided"),
            Self::NonNullTerminal => f.write_str("last label is not null"),
            Self::NullNonTerminal => f.write_str("non-terminal label is null"),
            Self::StrEmpty => f.write_str("string was empty"),
            Self::StrNotAscii => f.write_str("string was not ASCII"),
            Self::UnexpectedEom => f.write_str("unexpected end of message"),
        }
    }
}

impl std::error::Error for Error {}
