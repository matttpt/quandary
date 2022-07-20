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

//! File system–based parsing of zone files, with built-in support for
//! `$INCLUDE` directives.
//!
//! This module's [`Parser`] structure mirrors the general-purpose
//! [`Parser`](super::Parser) of the parent module, but instead of a
//! stream, it accepts a file path. It automatically handles `$INCLUDE`
//! directives, interpreting relative paths relative to the including
//! file's path. Nested includes are permitted up to a maximum depth
//! configured when the [`Parser`] is created.
//!
//! This module's [`Line`] structure and [`error`] submodule likewise
//! mirror [`Line`](`super::Line`) and [`error`](`super::error`) in the
//! parent module. The significant differences are the addition of path
//! information to returned data and the addition of extra failure modes
//! related to `$INCLUDE` processing.

use std::fs::File;
use std::io;
use std::iter;
use std::path::Path;
use std::rc::Rc;

use super::{LineContent, ParsedRr};

pub mod error;

pub use error::{Error, Result};
use error::{ErrorKind, FailedToOpenInclude, IncludesTooDeep, InvalidPath};

/// A zone file parser that works from the file system and automatically
/// handles `$INCLUDE` directives. See the
/// [`module-level documentation`](`self`) for more information.
pub struct Parser {
    files: Vec<(Rc<Path>, usize, super::Parser<File>)>,
    max_depth: usize,
}

/// A line with a record as returned by [`Parser::next`].
#[derive(Debug)]
pub struct Line {
    pub path: Rc<Path>,
    pub number: usize,
    pub record: ParsedRr,
}

impl Parser {
    /// Opens the zone file at `path` and creates a new [`Parser`] to
    /// read it. `$INCLUDE` directives will be processed up to the
    /// specified maximum depth (where `0` disables `$INCLUDE`
    /// directives and `1` disallows nested `$INCLUDE`s).
    pub fn open(path: impl AsRef<Path>, max_depth: usize) -> io::Result<Self> {
        // NOTE: for the first file record, the "included from" line
        // number (the middle entry of the tuple) is a placeholder that
        // is never used.
        let file_handle = File::open(path.as_ref())?;
        let file_record = (path.as_ref().into(), 0, super::Parser::new(file_handle));
        let files = vec![file_record];
        Ok(Self { files, max_depth })
    }
}

impl Iterator for Parser {
    type Item = Result<Line>;

    fn next(&mut self) -> Option<Self::Item> {
        // We must read the length before mutably borrowing from files
        // below.
        let depth = match self.files.len() {
            // The value is actually never used when the length is 0. We
            // do this simply to avoid "subtract with overflow" panics.
            0 => 0,
            n => n - 1,
        };

        // Try to get the current file. If none, we've reached the end
        // of the original file (or encountered an error and cleared the
        // stack to end iteration).
        let (path, _, parser) = match self.files.last_mut() {
            Some(last) => last,
            None => return None,
        };

        // Drive the current file's parser. If it has reached EOF, pop
        // it from the stack and try this method again.
        let next = match parser.next() {
            Some(next) => next,
            None => {
                let (_, _, parser) = self.files.pop().unwrap();
                if let Some((_, _, previous_parser)) = self.files.last_mut() {
                    previous_parser.update_context_from_include(parser);
                    return self.next();
                } else {
                    return None;
                }
            }
        };

        // The current file's parser gave us something. Let's hope it's
        // a line and not an error!
        let line = match next {
            Ok(line) => line,
            Err(err) => {
                let path = Box::from(path.as_ref());
                self.files.clear();
                let kind = match err {
                    super::error::Error::Io(io_err) => ErrorKind::GeneralIo(io_err),
                    super::error::Error::Syntax(details) => ErrorKind::Syntax(details),
                };
                return Some(Err(Error { path, kind }));
            }
        };

        // Great, it's a line! Process it as necessary.
        match line.content {
            LineContent::Record(record) => Some(Ok(Line {
                path: path.clone(),
                number: line.number,
                record,
            })),
            LineContent::Include(include) => {
                // Ensure that we don't exceed the depth limit.
                if depth >= self.max_depth {
                    let path = Box::from(path.as_ref());
                    let chain = make_include_chain(&self.files, line.number);
                    self.files.clear();
                    return Some(Err(Error {
                        path,
                        kind: ErrorKind::IncludesTooDeep(IncludesTooDeep {
                            line: line.number,
                            chain,
                        }),
                    }));
                }

                // Open the included file.
                let new_path = match compute_path(path, &include.path) {
                    Some(p) => p,
                    None => {
                        let path = Box::from(path.as_ref());
                        self.files.clear();
                        return Some(Err(Error {
                            path,
                            kind: ErrorKind::InvalidPath(InvalidPath { line: line.number }),
                        }));
                    }
                };
                let file_handle = match File::open(&new_path) {
                    Ok(f) => f,
                    Err(io_err) => {
                        let path = Box::from(path.as_ref());
                        self.files.clear();
                        return Some(Err(Error {
                            path,
                            kind: ErrorKind::FailedToOpenInclude(FailedToOpenInclude {
                                line: line.number,
                                path: Box::from(new_path.as_ref()),
                                io_err,
                            }),
                        }));
                    }
                };

                // Create the new super::Parser and use it.
                let new_parser = parser.new_for_include(file_handle, include.origin);
                self.files.push((new_path, line.number, new_parser));
                self.next()
            }
        }
    }
}

/// Converts the internal `files` stack of a [`Parser`] into a list
/// showing the paths that have been included and the location of the
/// `$INCLUDE` line in each.
fn make_include_chain(
    stack: &[(Rc<Path>, usize, super::Parser<File>)],
    current_line_number: usize,
) -> Vec<(Box<Path>, usize)> {
    stack
        .iter()
        .map(|(path, _, _)| path.as_ref().into())
        .zip(
            stack
                .iter()
                .skip(1)
                .map(|(_, line_included_from, _)| *line_included_from)
                .chain(iter::once(current_line_number)),
        )
        .collect()
}

/// Computes the path of an included file by converting the path into a
/// [`Path`] and then interpreting it relative to the including file's
/// path.
///
/// This assumes that `includer_path` has a parent (see
/// [`Path::parent`]); it will panic if not. Since the includer path
/// has been successfully opened by the time this is called, this should
/// be a safe assumption.
fn compute_path(includer_path: &Path, included_path: &[u8]) -> Option<Rc<Path>> {
    let specified_path = convert_to_path(included_path)?;
    let previous_parent = includer_path
        .parent()
        .expect("including file's path has no parent");
    Some(previous_parent.join(specified_path).into())
}

/// Converts octets to a [`Path`] on Unix systems.
#[cfg(unix)]
fn convert_to_path(octets: &[u8]) -> Option<&Path> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    Some(Path::new(OsStr::from_bytes(octets)))
}

/// Converts octets to a [`Path`] on non-Unix systems.
#[cfg(not(unix))]
fn convert_to_path(octets: &[u8]) -> Option<&Path> {
    std::str::from_utf8(octets).ok().map(Path::new)
}
