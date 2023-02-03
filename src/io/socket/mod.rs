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

//! Provides target-specific socket support when available.
//!
//! Certain desirable network socket features are not available in the
//! Rust standard library and require target-specific implementations
//! (if the target supports them in the first place). Currently, the
//! features of interest are:
//!
//! 1. The ability to call `accept` with a timeout on a listening TCP
//!    socket. (Since this is not part of the standard Bekeley sockets
//!    API, what we actually implement, when possible, is a
//!    `poll_accept` method with a timeout, which e.g. on Unix systems
//!    can be built with the `poll` system call.)
//!
//! 2. The ability to select the local address we use when communicating
//!    over UDP. This involves both determining the destination address
//!    used in UDP packets we receive and asking the operating system to
//!    use that as the source address when we send replies.
//!
//! These socket features are not strictly required for Quandary to
//! work. However, certain Quandary features may not be available
//! without them. General features requiring specialized socket
//! implementations are documented below; I/O provider-specific features
//! are noted in their own documentation.
//!
//! # General features requiring specialized socket implementations
//!
//! 1. **UDP local address selection.** Many operating systems allow
//!    a program to listen on all local IP addresses by binding to
//!    `0.0.0.0` (for IPv4) or `::` (for IPv6). However, since UDP is
//!    stateless, the operating system may not know what source address
//!    to use when we send a UDP datagram. Systems may have heuristics
//!    to make a best guess, but the only way to *guarantee* that the
//!    server replies to a particular UDP message from the address the
//!    client used (and expects to hear back from) is (a) to get the
//!    system to tell us what IP address the client sent the datagram
//!    to, and (b) to then instruct the system to use that as the source
//!    address when we send the reply.
//!
//!    [RFC 4532] standardizes how the Berkeley sockets API should
//!    accommodate this for IPv6, but different targets have different
//!    APIs for IPv4. (See this informative [write-up][PowerDNS blog]
//!    for more details.) Furthermore, it's not supported by the Rust
//!    standard library.
//!
//!    This feature is currently available on **Linux**, **NetBSD**, and
//!    **FreeBSD**. It is automatically used if it's available. You can
//!    determine whether your build has it by checking
//!    [`SUPPORTS_LOCAL_ADDRESS_SELECTION`].
//!
//! [PowerDNS blog]: https://blog.powerdns.com/2012/10/08/on-binding-datagram-udp-sockets-to-the-any-addresses/
//! [RFC 4532]: https://datatracker.ietf.org/doc/html/rfc3542

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The API that the concrete, target-specific [`TcpListener`] must
/// implement.
pub(crate) trait TcpListenerApi: Sized {
    /// Whether this implementation has a functional
    /// [`poll_accept`](TcpListenerApi::poll_accept) method.
    const POLL_ACCEPT_WORKS: bool;

    /// Creates a new listener bound to the provided address.
    fn bind(addr: SocketAddr) -> io::Result<Self>;

    /// Sets whether the listener is in non-blocking mode.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;

    /// When supported, blocks until a new connection is available, the
    /// provided timeout expires, or the call is interrupted. Returns
    /// whether a new connection is available.
    ///
    /// On targets that do not support this, this method should
    /// immediately return `Ok(true)` and
    /// [`POLL_ACCEPT_WORKS`][`TcpListenerApi::POLL_ACCEPT_WORKS`]
    /// should be `false`.
    fn poll_accept(&self, timeout: Duration) -> io::Result<bool>;

    /// Accepts a new connection.
    fn accept(&self) -> io::Result<(TcpStream, SocketAddr)>;
}

/// The API that the concrete, target-specific [`UdpSocket`] must
/// implement.
pub(crate) trait UdpSocketApi: Clone + Sized {
    /// Stores the local address for UDP local address selection. When
    /// this is not supported, implementations may set this to `()`.
    type LocalAddr;

    /// Whether this implementation supports local address selection.
    const SUPPORTS_LOCAL_ADDRESS_SELECTION: bool;

    /// Creates a new UDP socket bound to the provided address.
    fn bind(addr: SocketAddr) -> io::Result<Self>;

    /// Sets the read timeout of the socket.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Receives a datagram.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Self::LocalAddr)>;

    /// Sends a datagram.
    fn send(&mut self, buf: &[u8], dest: SocketAddr, src: Self::LocalAddr) -> io::Result<usize>;
}

/// The implementation of [`TcpListener`] for this target.
#[cfg_attr(unix, path = "unix_tcp.rs")]
#[cfg_attr(not(unix), path = "std_tcp.rs")]
mod tcp_impl;

/// The implementation of [`UdpSocket`] for this target.
#[cfg_attr(
    any(target_os = "linux", target_os = "netbsd", target_os = "freebsd"),
    path = "unix_udp_localaddr.rs"
)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "netbsd", target_os = "freebsd")),
    path = "std_udp.rs"
)]
mod udp_impl;

pub(crate) use tcp_impl::TcpListener;
pub(crate) use udp_impl::UdpSocket;

/// Whether local address selection is supported for UDP sockets on this
/// target.
pub const SUPPORTS_LOCAL_ADDRESS_SELECTION: bool = UdpSocket::SUPPORTS_LOCAL_ADDRESS_SELECTION;

#[cfg(feature = "tokio")]
mod tokio {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::{UdpSocket, UdpSocketApi};

    type LocalAddr = <UdpSocket as UdpSocketApi>::LocalAddr;

    /// The API that the concrete, target-specific
    /// [`AsyncUdpSocket`](super::AsyncUdpSocket) must implement.
    pub(crate) trait AsyncUdpSocketApi: Clone + Sized {
        /// Creates a new UDP socket bound to the provided address.
        fn bind(addr: SocketAddr) -> io::Result<Self>;

        /// Attempts to receive a datagram. This is a low-level
        /// method to be provided by implementors; users should call
        /// [`AsyncUdpSocketApi::recv`] to get a [`Future`] instead.
        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr, LocalAddr)>>;

        /// Attempts to send a datagram. This is a low-level
        /// method to be provided by implementors; users should call
        /// [`AsyncUdpSocketApi::send`] to get a [`Future`] instead.
        fn poll_send(
            &mut self,
            cx: &mut Context<'_>,
            buf: &[u8],
            dest: SocketAddr,
            src: LocalAddr,
        ) -> Poll<io::Result<usize>>;

        /// Receives a datagram.
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> RecvFut<'a, Self> {
            RecvFut { socket: self, buf }
        }

        /// Sends a datagram.
        fn send<'a>(
            &'a mut self,
            buf: &'a [u8],
            dest: SocketAddr,
            src: LocalAddr,
        ) -> SendFut<'a, Self> {
            SendFut {
                socket: self,
                buf,
                dest,
                src,
            }
        }
    }

    /// The [`Future`] returned by [`AsyncUdpSocketApi::recv`].
    pub(crate) struct RecvFut<'a, S> {
        socket: &'a mut S,
        buf: &'a mut [u8],
    }

    impl<'a, S> Future for RecvFut<'a, S>
    where
        S: AsyncUdpSocketApi,
    {
        type Output = io::Result<(usize, SocketAddr, LocalAddr)>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.socket.poll_recv(cx, this.buf)
        }
    }

    /// The [`Future`] returned by [`AsyncUdpSocketApi::send`].
    pub(crate) struct SendFut<'a, S> {
        socket: &'a mut S,
        buf: &'a [u8],
        dest: SocketAddr,
        src: LocalAddr,
    }

    impl<'a, S> Future for SendFut<'a, S>
    where
        S: AsyncUdpSocketApi,
    {
        type Output = io::Result<usize>;

        #[allow(clippy::unit_arg)]
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.socket.poll_send(cx, this.buf, this.dest, this.src)
        }
    }
}

#[cfg(feature = "tokio")]
pub(crate) use self::{tokio::AsyncUdpSocketApi, udp_impl::AsyncUdpSocket};
