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

//! Parsing of domain names.

use std::io::{self, Read};
use std::rc::Rc;

use super::{Error, ErrorKind, Parser, Position, Result};
use crate::name::{self, Name, NameBuilder};

impl<S: Read> Parser<S> {
    /// Tries to parse a domain name, including support for the `@`
    /// shorthand for the current origin. The Reader should be advanced
    /// to the next field before calling this method; if it immediately
    /// encounters a field-ending character, it will return the root
    /// name `.`, which is probably not what you want.
    pub(super) fn parse_name(&mut self) -> Result<Rc<Name>> {
        let start_position = self.reader.position();
        if self.parse_origin_name()? {
            if let Some(origin) = self.context.origin.as_ref() {
                Ok(origin.clone())
            } else {
                Err(Error::new(start_position, ErrorKind::AtWhenOriginNotSet))
            }
        } else if self.parse_root_name()? {
            Ok(Name::root().to_owned().into())
        } else {
            self.parse_non_root_name()
        }
    }

    /// Tries to parse the name `@`, which stands for the current
    /// origin, and returns whether it was found.
    fn parse_origin_name(&mut self) -> io::Result<bool> {
        self.reader.expect_field(b"@")
    }

    /// Tries to parse the root name `.`, and returns whether it was
    /// found.
    fn parse_root_name(&mut self) -> io::Result<bool> {
        self.reader.expect_field(b".")
    }

    /// Internal helper to try to parse a domain name. If a PQDN is
    /// parsed, it will be completed using the current origin if
    /// possible. This method will not sucessfully parse the root name
    /// `.`, so one should check for it with [`Parser::parse_root_name`]
    /// first.
    fn parse_non_root_name(&mut self) -> Result<Rc<Name>> {
        let name_start_position = self.reader.position();
        let mut label_start_position = self.reader.position();
        let mut name_builder = NameBuilder::new();

        while let Some(octet) = self.reader.read_field_octet()? {
            if octet == b'\\' {
                let escaped_octet = self.parse_escape()?;
                name_builder.try_push(escaped_octet).map_err(|e| {
                    build_label_parse_error(e, name_start_position, label_start_position)
                })?;
            } else if octet == b'.' {
                name_builder.next_label().map_err(|e| {
                    build_label_parse_error(e, name_start_position, label_start_position)
                })?;
                label_start_position = self.reader.position();
            } else {
                name_builder.try_push(octet).map_err(|e| {
                    build_label_parse_error(e, name_start_position, label_start_position)
                })?;
            }
        }

        if name_builder.is_fully_qualified() {
            name_builder
                .finish()
                .map(Into::into)
                .map_err(|e| Error::new(name_start_position, ErrorKind::InvalidName(e)))
        } else if let Some(origin) = self.context.origin.as_ref() {
            name_builder
                .finish_with_suffix(origin)
                .map(Into::into)
                .map_err(|e| Error::new(name_start_position, ErrorKind::InvalidName(e)))
        } else {
            Err(Error::new(
                name_start_position,
                ErrorKind::PqdnWhenOriginNotSet,
            ))
        }
    }
}

/// Generates a parse error from a [`name::Error`]. The parse error is
/// tailored to whether the [`name::Error`] signals a problem with the
/// current label or a problem with the entire name.
fn build_label_parse_error(
    error: name::Error,
    name_start_position: Position,
    label_start_position: Position,
) -> Error {
    if error == name::Error::LabelTooLong {
        Error::new(label_start_position, ErrorKind::InvalidLabel(error))
    } else {
        Error::new(name_start_position, ErrorKind::InvalidName(error))
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::super::tests::make_parser;
    use super::*;

    #[test]
    fn parsing_works() {
        assert_eq!(
            *make_parser(b"quandary.test. extra data")
                .parse_name()
                .unwrap(),
            *"quandary.test.".parse::<Box<Name>>().unwrap(),
        );
    }

    #[test]
    fn escaping_works() {
        assert_eq!(
            *make_parser(b"test\\.with.a.dot.").parse_name().unwrap(),
            *"test\\.with.a.dot.".parse::<Box<Name>>().unwrap(),
        );
        assert_eq!(
            *make_parser(b"test\\000with.a.null.").parse_name().unwrap(),
            *"test\\000with.a.null.".parse::<Box<Name>>().unwrap(),
        );
    }

    #[test]
    fn parsing_pqdns_with_origin_set_works() {
        let mut parser = make_parser(b"quandary");
        parser.context.origin = Some("test.".parse::<Box<Name>>().unwrap().into());
        assert_eq!(
            *parser.parse_name().unwrap(),
            *"quandary.test.".parse::<Box<Name>>().unwrap(),
        );
    }

    #[test]
    fn parser_rejects_pqdn_without_origin_set() {
        assert!(matches!(
            make_parser(b"pqdn").parse_name(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::PqdnWhenOriginNotSet,
        ));
    }

    #[test]
    fn parsing_at_shorthand_with_origin_set_works() {
        let mut parser = make_parser(b"@ extra data");
        let origin: Rc<Name> = "test.".parse::<Box<Name>>().unwrap().into();
        parser.context.origin = Some(origin.clone());
        assert_eq!(*parser.parse_name().unwrap(), *origin);
    }

    #[test]
    fn parser_rejects_at_shorthand_without_origin_set() {
        assert!(matches!(
            make_parser(b"@").parse_name(),
            Err(Error::Syntax(details)) if details.kind == ErrorKind::AtWhenOriginNotSet,
        ));
    }

    #[test]
    fn parsing_root_works() {
        assert_eq!(
            *make_parser(b". extra data").parse_name().unwrap(),
            *Name::root(),
        );
    }
}
