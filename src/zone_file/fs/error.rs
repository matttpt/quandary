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

//! Error types for file system–based zone file parsing.
//!
//! This is the [`fs`](`super`) module's counterpart to general zone
//! file parsing's [`error`](`super::super::error`) module.

use std::fmt;
use std::io;
use std::path::Path;

use super::super::error::ErrorDetails;

////////////////////////////////////////////////////////////////////////
// ERROR STRUCTURE                                                    //
////////////////////////////////////////////////////////////////////////

/// Represents errors that may occur during file system–based zone file
/// parsing.
#[derive(Debug)]
pub struct Error {
    pub(super) path: Box<Path>,
    pub(super) kind: ErrorKind,
}

impl Error {
    /// Returns the path of the zone file that was being processed when
    /// the error occurred.
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Returns the kind of error that occurred.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            ErrorKind::GeneralIo(io_err) => {
                write!(f, "I/O error reading {}: {}", self.path.display(), io_err)
            }
            ErrorKind::InvalidPath(ip) => write!(
                f,
                "invalid path provided at {} line {}",
                self.path.display(),
                ip.line,
            ),
            ErrorKind::FailedToOpenInclude(ftoi) => {
                write!(
                    f,
                    "failed to open file {} (included at {} line {}): {}",
                    ftoi.path.display(),
                    self.path.display(),
                    ftoi.line,
                    ftoi.io_err,
                )
            }
            ErrorKind::IncludesTooDeep(itd) => {
                write!(
                    f,
                    "nested $INCLUDEs are too deep at {} line {}; the maximum depth is {}",
                    self.path.display(),
                    itd.line,
                    itd.chain.len() - 1, // The length should always be non-zero.
                )?;
                let mut iter = itd.chain.iter();
                if let Some((path, line)) = iter.next() {
                    write!(
                        f,
                        ". The $INCLUDE chain so far is {} (line {})",
                        path.display(),
                        line,
                    )?;
                    for (path, line) in iter {
                        write!(f, " -> {} (line {})", path.display(), line)?;
                    }
                    f.write_str(".")?;
                }
                Ok(())
            }
            ErrorKind::Syntax(details) => write!(
                f,
                "{} at {} line {} column {}",
                details.kind,
                self.path.display(),
                details.position.line,
                details.position.column,
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A result type for file system–based zone file parsing.
pub type Result<T> = std::result::Result<T, Error>;

////////////////////////////////////////////////////////////////////////
// ERROR KINDS                                                        //
////////////////////////////////////////////////////////////////////////

/// Kinds of errors that may occur during file system–based zone file
/// parsing.
#[derive(Debug)]
pub enum ErrorKind {
    /// I/O errors encountered while reading a zone file. This
    /// corresponds to the [`Error::Io`](`super::super::Error::Io`)
    /// variant in general zone file parsing.
    GeneralIo(io::Error),

    /// An `$INCLUDE` directive had an invalid path. This occurs on
    /// systems where not all sequences of octets are valid paths.
    InvalidPath(InvalidPath),

    /// There was an I/O error while opening an included file.
    FailedToOpenInclude(FailedToOpenInclude),

    /// The chain of `$INCLUDE` directives has exceeded the maximum
    /// configured for the [`Parser`](super::Parser).
    IncludesTooDeep(IncludesTooDeep),

    /// Syntax errors. This corresponds to the
    /// [`Error::Syntax`](`super::super::Error::Syntax`) variant in
    /// general zone file parsing.
    Syntax(ErrorDetails),
}

/// Extra data describing an invalid path error.
#[derive(Debug)]
pub struct InvalidPath {
    pub(super) line: usize,
}

impl InvalidPath {
    /// Returns the line with the `$INCLUDE` directive at which the
    /// invalid path was found.
    pub fn line(&self) -> usize {
        self.line
    }
}

/// Extra data describing a failure to open an included file.
#[derive(Debug)]
pub struct FailedToOpenInclude {
    pub(super) line: usize,
    pub(super) path: Box<Path>,
    pub(super) io_err: io::Error,
}

impl FailedToOpenInclude {
    /// Returns the line with the `$INCLUDE` directive where the error
    /// occurred.
    pub fn line(&self) -> usize {
        self.line
    }

    /// Returns the path of the included file that could not be opened.
    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Returns the [`io::Error`] that caused this error.
    pub fn io_error(&self) -> &io::Error {
        &self.io_err
    }
}

/// Extra data describing an excessively long `$INCLUDE` chain.
#[derive(Debug)]
pub struct IncludesTooDeep {
    pub(super) line: usize,
    pub(super) chain: Vec<(Box<Path>, usize)>,
}

impl IncludesTooDeep {
    /// Returns the line with the `$INCLUDE` directive where the error
    /// occurred.
    pub fn line(&self) -> usize {
        self.line
    }

    /// Returns the chain of `$INCLUDE` directives up to the point of
    /// the error. Each tuple contains the path of a file and the line
    /// in that file with the `$INCLUDE` directive that included the
    /// next file in the chain. The final entry is the path and line at
    /// which the error occurred.
    pub fn chain(&self) -> &[(Box<Path>, usize)] {
        &self.chain
    }
}
