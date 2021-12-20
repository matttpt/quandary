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

//! Implementation of parsing and validation of on-the-wire names.

use arrayvec::ArrayVec;

use super::{new_boxed_name, Error, Name, NameBuilder, MAX_LABEL_LEN, MAX_N_LABELS, MAX_WIRE_LEN};

////////////////////////////////////////////////////////////////////////
// VALIDATION AND PARSING OF UNCOMPRESSED ON-THE-WIRE NAMES           //
////////////////////////////////////////////////////////////////////////

/// Parses an uncompressed name present at the beginning of `octets`.
/// The parameter `use_all` controls whether to expect the name to
/// occupy the entire buffer. This is the implementation of
/// [`Name::try_from_uncompressed`] and
/// [`Name::try_from_uncompressed_all`].
pub fn parse_uncompressed_name(octets: &[u8], use_all: bool) -> Result<(Box<Name>, usize), Error> {
    let mut offset = 0;
    let mut finished = false;
    let mut label_offsets = ArrayVec::<u8, MAX_N_LABELS>::new();
    while !finished && offset < octets.len() {
        let label_len = octets[offset];
        if label_len > (MAX_LABEL_LEN as u8) {
            return Err(Error::LabelTooLong);
        } else if label_len == 0 {
            finished = true;
        }
        label_offsets.push(offset as u8);
        offset += label_len as usize + 1;
        if offset > MAX_WIRE_LEN {
            // We check the offset against the maximum wire length in
            // each iteration (as opposed to once at the end) to ensure
            // that we never oveflow label_offsets.
            return Err(Error::NameTooLong);
        }
    }

    if !finished {
        Err(Error::UnexpectedEom)
    } else if use_all && offset < octets.len() {
        Err(Error::ExtraData)
    } else {
        let wire_len = offset;
        let name = unsafe {
            // SAFETY: we have checked that the on-the-wire
            // representation is a valid domain name, and we promise
            // that we've computed label_offsets correctly.
            new_boxed_name(wire_len, &label_offsets, &[&octets[..wire_len]])
        };
        Ok((name, wire_len))
    }
}

/// Validates an uncompressed name present at the beginning of `octets`.
/// The parameter `use_all` controls whether to expect the name to
/// occupy the entire buffer. This is the implementation of
/// [`Name::validate_uncompressed`] and
/// [`Name::validate_uncompressed_all`].
pub fn validate_uncompressed_name(octets: &[u8], use_all: bool) -> Result<usize, Error> {
    let mut offset = 0;
    let mut finished = false;
    while !finished && offset < octets.len() {
        let label_len = octets[offset];
        if label_len > (MAX_LABEL_LEN as u8) {
            return Err(Error::LabelTooLong);
        } else if label_len == 0 {
            finished = true;
        }
        offset += label_len as usize + 1;
        if offset > MAX_WIRE_LEN {
            // Unlike above, we don't need to check this on every
            // iteration to avoid overflowing label_offsets (since we're
            // not keeping track of them here). But doing so *does*
            // prevent us from wasting a lot of time processing a
            // massive but otherwise valid domain name.
            return Err(Error::NameTooLong);
        }
    }

    if !finished {
        Err(Error::UnexpectedEom)
    } else if use_all && offset < octets.len() {
        Err(Error::ExtraData)
    } else {
        Ok(offset)
    }
}

////////////////////////////////////////////////////////////////////////
// PARSING OF COMPRESSED ON-THE-WIRE NAMES                            //
////////////////////////////////////////////////////////////////////////

/// Parses a compressed name starting at index `start` of `octets`.
/// Pointers are followed. Indices given in pointers are treated as
/// indices of `octets`, so the intention is for an entire DNS message
/// to be passed in `octets`. This is the implementation of
/// [`Name::try_from_compressed`].
pub fn parse_compressed_name(octets: &[u8], start: usize) -> Result<(Box<Name>, usize), Error> {
    let mut builder = NameBuilder::new();
    let mut chunk_start = start;
    let mut finished = false;
    let mut wire_len_of_first_chunk = None;

    while !finished {
        match parse_chunk(octets, chunk_start, &mut builder)? {
            Chunk::Last(len) => {
                wire_len_of_first_chunk.get_or_insert(len);
                finished = true;
            }
            Chunk::Pointer(len, pointer) => {
                wire_len_of_first_chunk.get_or_insert(len);
                chunk_start = pointer as usize;
            }
        }
    }

    Ok((builder.finish()?, wire_len_of_first_chunk.unwrap()))
}

/// We view compressed on-the-wire names in terms of a number of
/// contiguous chunks; there may be multiple such chunks through the use
/// of pointers. All but the last chunk end with a pointer; the last
/// chunk ends with the null label.
///
/// This `enum` reports information about a parsed chunk.
enum Chunk {
    /// This chunk is the last chunk in the name. The length in octets
    /// is reported.
    Last(usize),

    /// This chunk ends with a pointer, so it is not the last. The length
    /// in octets and the value of the pointer are reported.
    Pointer(usize, u16),
}

/// Parses a chunk of a compressed on-the-wire name in `octets` starting
/// at index `start`. Labels contained in the chunk are written to the
/// passed [`NameBuilder`]. On success, details about the chunk are
/// returned. Note that on failure, the state of the [`NameBuilder`] is
/// undefined, since the calling code above doesn't need to try to
/// recover.
fn parse_chunk(octets: &[u8], start: usize, builder: &mut NameBuilder) -> Result<Chunk, Error> {
    let mut index = start;
    let mut finished = false;

    while !finished && index < octets.len() {
        let len = octets[index];
        if len & 0xc0 == 0xc0 {
            let pointer = parse_pointer(octets, start, index)?;
            return Ok(Chunk::Pointer(index + 2 - start, pointer));
        } else if len > (MAX_LABEL_LEN as u8) {
            return Err(Error::LabelTooLong);
        } else if len == 0 {
            finished = true;
            index += 1;
        } else {
            let content_start = index + 1;
            let content_end = index + 1 + len as usize;
            if content_end > octets.len() {
                return Err(Error::UnexpectedEom);
            }
            builder.try_push_slice(&octets[content_start..content_end])?;
            builder.next_label()?;
            index = content_end;
        }
    }

    if !finished {
        Err(Error::UnexpectedEom)
    } else {
        Ok(Chunk::Last(index - start))
    }
}

/// Parses a pointer at `index` in `octets`. This also checks that the
/// pointer refers to an index *earlier* than the start of the chunk it
/// is in (`chunk_start`).
fn parse_pointer(octets: &[u8], chunk_start: usize, index: usize) -> Result<u16, Error> {
    if index + 1 < octets.len() {
        let pointer_bytes = [octets[index], octets[index + 1]];
        let pointer = u16::from_be_bytes(pointer_bytes) & (!0xc000);
        if (pointer as usize) >= chunk_start {
            // According to RFC 1035 § 4.1.4, pointers point to a
            // *prior* occurrence of the name. (Importantly, this
            // prevents loops!)
            Err(Error::InvalidPointer)
        } else {
            Ok(pointer)
        }
    } else {
        Err(Error::UnexpectedEom)
    }
}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    ////////////////////////////////////////////////////////////////////
    // COMMON TEST IMPLEMENTATIONS FOR UNCOMPRESSED PARSING AND       //
    // VALIDATION                                                     //
    ////////////////////////////////////////////////////////////////////

    type TestedFn<T> = fn(&[u8], bool) -> Result<T, Error>;

    fn rejects_extra_data_impl<T: Debug>(f: TestedFn<T>) {
        assert_eq!(
            f(b"\x07example\x04test\x00junk", true).unwrap_err(),
            Error::ExtraData
        );
    }

    fn rejects_long_label_impl<T: Debug>(f: TestedFn<T>) {
        assert_eq!(
            f(
                b"\x40xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x00",
                true
            )
            .unwrap_err(),
            Error::LabelTooLong
        );
    }

    fn rejects_long_name_impl<T: Debug>(f: TestedFn<T>) {
        assert_eq!(
            f(
                b"\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x00",
                true
            )
            .unwrap_err(),
            Error::NameTooLong
        );
    }

    fn rejects_unexpected_eom_impl<T: Debug>(f: TestedFn<T>) {
        assert_eq!(
            f(b"\x07example\x04tes", true).unwrap_err(),
            Error::UnexpectedEom
        );
    }

    ////////////////////////////////////////////////////////////////////
    // TESTS FOR parse_uncompressed_name                              //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn parse_uncompressed_name_accepts_valid_names() {
        let wire_repr_and_junk = b"\x07example\x04test\x00junk";
        let wire_repr = &wire_repr_and_junk[..14];
        let target: Box<Name> = "example.test.".parse().unwrap();
        assert_eq!(
            parse_uncompressed_name(wire_repr, false),
            Ok((target.clone(), 14))
        );
        assert_eq!(
            parse_uncompressed_name(wire_repr, true),
            Ok((target.clone(), 14))
        );
        assert_eq!(
            parse_uncompressed_name(wire_repr_and_junk, false),
            Ok((target, 14))
        );
    }

    #[test]
    fn parse_uncompressed_name_rejects_extra_data() {
        rejects_extra_data_impl(parse_uncompressed_name);
    }

    #[test]
    fn parse_uncompressed_name_rejects_long_label() {
        rejects_long_label_impl(parse_uncompressed_name);
    }

    #[test]
    fn parse_uncompressed_name_rejects_long_name() {
        rejects_long_name_impl(parse_uncompressed_name);
    }

    #[test]
    fn parse_uncompressed_name_rejects_unexpected_eom() {
        rejects_unexpected_eom_impl(parse_uncompressed_name);
    }

    ////////////////////////////////////////////////////////////////////
    // TESTS FOR validate_uncompressed_name                           //
    ////////////////////////////////////////////////////////////////////

    #[test]
    fn validate_uncompressed_name_accepts_valid_names() {
        let wire_repr_and_junk = b"\x07example\x04test\x00junk";
        let wire_repr = &wire_repr_and_junk[..14];
        assert_eq!(validate_uncompressed_name(wire_repr, false), Ok(14));
        assert_eq!(validate_uncompressed_name(wire_repr, true), Ok(14));
        assert_eq!(
            validate_uncompressed_name(wire_repr_and_junk, false),
            Ok(14)
        );
    }

    #[test]
    fn validate_uncompressed_name_rejects_extra_data() {
        rejects_extra_data_impl(validate_uncompressed_name);
    }

    #[test]
    fn validate_uncompressed_name_rejects_long_label() {
        rejects_long_label_impl(validate_uncompressed_name);
    }

    #[test]
    fn validate_uncompressed_name_rejects_long_name() {
        rejects_long_name_impl(validate_uncompressed_name);
    }

    #[test]
    fn validate_uncompressed_name_rejects_unexpected_eom() {
        rejects_unexpected_eom_impl(validate_uncompressed_name);
    }

    ////////////////////////////////////////////////////////////////////
    // TESTS FOR parse_compressed_name                                //
    ////////////////////////////////////////////////////////////////////

    /// A shim to use some of the uncompressed tests for
    /// `parse_compressed_name`.
    fn parse_compressed_name_shim(
        octets: &[u8],
        _use_all: bool,
    ) -> Result<(Box<Name>, usize), Error> {
        parse_compressed_name(octets, 0)
    }

    #[test]
    fn parse_compressed_name_accepts_valid_uncompressed_names() {
        let octets = b"junk\x07example\x04test\x00junk";
        let target: Box<Name> = "example.test.".parse().unwrap();
        assert_eq!(parse_compressed_name(octets, 4), Ok((target, 14)));
    }

    #[test]
    fn parse_compressed_name_accepts_valid_compressed_names() {
        let octets = b"junk\x04test\x00junk\x07example\xc0\x04junk";
        let target: Box<Name> = "example.test.".parse().unwrap();
        assert_eq!(parse_compressed_name(octets, 14), Ok((target, 10)));
    }

    #[test]
    fn parse_compressed_name_rejects_long_label() {
        rejects_long_label_impl(parse_compressed_name_shim);
    }

    #[test]
    fn parse_compressed_name_rejects_long_label_with_pointers() {
        assert_eq!(
            parse_compressed_name(
                b"\x01x\
                  \x40xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
                  \x00\x01x\xc0\x00",
                68
            ),
            Err(Error::LabelTooLong),
        );
    }

    #[test]
    fn parse_compressed_name_rejects_long_name() {
        rejects_long_name_impl(parse_compressed_name_shim);
    }

    #[test]
    fn parse_compressed_name_rejects_long_name_with_pointers() {
        assert_eq!(
            parse_compressed_name(
                b"\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \x00\
                  \x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\x01x\
                  \xc0\x00",
                225
            ),
            Err(Error::NameTooLong),
        );
    }

    #[test]
    fn parse_compressed_name_rejects_unexpected_eom() {
        rejects_unexpected_eom_impl(parse_compressed_name_shim);
    }

    #[test]
    fn parse_compressed_name_rejects_pointer_loops() {
        assert_eq!(
            parse_compressed_name(b"\xc0\x00", 0),
            Err(Error::InvalidPointer),
        );
        assert_eq!(
            parse_compressed_name(b"\x01a\x01b\xc0\x00", 2),
            Err(Error::InvalidPointer),
        );
    }

    #[test]
    fn parse_compressed_name_rejects_forward_pointers() {
        assert_eq!(
            parse_compressed_name(b"\x01x\xc0\x08junk\x00", 0),
            Err(Error::InvalidPointer),
        );
    }
}
