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
use std::net::{self, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::UdpSocketApi;

/// A UDP socket implementation using the Rust standard library.
#[derive(Clone)]
pub struct UdpSocket(Arc<net::UdpSocket>);

impl UdpSocketApi for UdpSocket {
    type LocalAddr = ();
    const SUPPORTS_LOCAL_ADDRESS_SELECTION: bool = false;

    fn bind(addr: SocketAddr) -> io::Result<Self> {
        net::UdpSocket::bind(addr).map(Arc::new).map(Self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, ())> {
        self.0.recv_from(buf).map(|(len, src)| (len, src, ()))
    }

    fn send(&mut self, buf: &[u8], dest: SocketAddr, _src: ()) -> io::Result<usize> {
        self.0.send_to(buf, dest)
    }
}
