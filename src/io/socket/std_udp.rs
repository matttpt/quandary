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

#[cfg(feature = "tokio")]
mod tokio {
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::task::{ready, Context, Poll};

    use tokio::io::ReadBuf;

    use super::super::AsyncUdpSocketApi;

    /// An asynchronous UDP socket implementation using Tokio and the
    /// Rust standard library.
    #[derive(Clone)]
    pub struct AsyncUdpSocket(Arc<tokio::net::UdpSocket>);

    impl AsyncUdpSocketApi for AsyncUdpSocket {
        fn bind(addr: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(addr)?;
            socket.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(socket)
                .map(Arc::new)
                .map(Self)
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr, ())>> {
            let mut read_buf = ReadBuf::new(buf);
            let res = ready!(self.0.poll_recv_from(cx, &mut read_buf));
            Poll::Ready(res.map(|socket_addr| (read_buf.filled().len(), socket_addr, ())))
        }

        fn poll_send(
            &mut self,
            cx: &mut Context<'_>,
            buf: &[u8],
            dest: SocketAddr,
            _src: (),
        ) -> Poll<io::Result<usize>> {
            self.0.poll_send_to(cx, buf, dest)
        }
    }
}

#[cfg(feature = "tokio")]
pub use self::tokio::AsyncUdpSocket;
