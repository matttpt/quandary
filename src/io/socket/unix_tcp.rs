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

use std::io;
use std::net::{self, SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};

use super::TcpListenerApi;

/// A TCP listener implementation wrapping
/// [`poll_accept`](TcpListenerApi::poll_accept) support around the
/// standard library [`TcpListener`](net::TcpListener) on Unix targets.
pub struct TcpListener(net::TcpListener);

impl TcpListenerApi for TcpListener {
    const POLL_ACCEPT_WORKS: bool = true;

    fn bind(addr: SocketAddr) -> io::Result<Self> {
        net::TcpListener::bind(addr).map(Self)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    fn poll_accept(&self, timeout: Duration) -> io::Result<bool> {
        let millis = timeout.as_millis().try_into().unwrap_or(i32::MAX);
        let mut poll_fds = [PollFd::new(self.0.as_raw_fd(), PollFlags::POLLIN)];
        poll(&mut poll_fds, millis).map(|n| n > 0).or_else(|e| {
            if e == Errno::EINTR {
                Ok(false)
            } else {
                Err(e.into())
            }
        })
    }

    fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.0.accept()
    }
}
