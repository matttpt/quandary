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

use std::io::{self, Error, ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;

use cfg_if::cfg_if;
use libc::{in6_addr, in6_pktinfo, in_addr};
use nix::cmsg_space;
use nix::sys::socket::{
    bind, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily, CmsgIterator,
    ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SockFlag, SockProtocol, SockType,
    SockaddrStorage,
};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::close;

#[cfg(any(target_os = "linux", target_os = "netbsd"))]
use libc::in_pktinfo;

use super::UdpSocketApi;

/// Each UDP socket corresponding to a single file descriptor has its
/// own control-message buffer, but they all share a copy of this
/// structure through an [`Arc`] smart pointer. This type's [`Drop`]
/// implementation closes the socket file descriptor.
#[derive(Clone)]
struct UdpSocketSharedData {
    fd: RawFd,
    bind_addr: IpAddr,
}

impl Drop for UdpSocketSharedData {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

impl AsRawFd for UdpSocketSharedData {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

////////////////////////////////////////////////////////////////////////
// SYNCHRONOUS UDP SOCKETS                                            //
////////////////////////////////////////////////////////////////////////

/// A UDP socket implementation, available on Linux, NetBSD, and FreeBSD
/// systems, with local address selection support.
pub struct UdpSocket {
    data: Arc<UdpSocketSharedData>,
    cmsg_buf: Vec<u8>,
}

impl Clone for UdpSocket {
    fn clone(&self) -> Self {
        // We must clone manually to ensure that a fresh
        // control-message buffer is allocated properly. The cmsg_space
        // macro pre-allocates a Vec of the appropriate size, but its
        // length remains zero until it's actually used in a recvmsg
        // call. Thus, if we clone cmsg_buf before it's used, the clone
        // won't actually allocate memory. Better to just call
        // make_cmsg_buf again.
        Self {
            data: self.data.clone(),
            cmsg_buf: make_cmsg_buf(self.data.bind_addr),
        }
    }
}

impl UdpSocketApi for UdpSocket {
    type LocalAddr = IpAddr;
    const SUPPORTS_LOCAL_ADDRESS_SELECTION: bool = true;

    fn bind(addr: SocketAddr) -> io::Result<Self> {
        let (data, cmsg_buf) = bind_impl(addr)?;
        Ok(Self {
            data: Arc::new(data),
            cmsg_buf,
        })
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        let timeval = match timeout {
            Some(t) => {
                if t.is_zero() {
                    // This error and message match the Rust standard
                    // library (see std::sys::unix::net).
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "cannot set a 0 duration timeout",
                    ));
                }
                TimeVal::microseconds(t.as_micros().try_into().unwrap_or(i64::MAX))
            }
            None => TimeVal::zero(),
        };
        setsockopt(self.data.fd, sockopt::ReceiveTimeout, &timeval).map_err(Into::into)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, IpAddr)> {
        recv_impl(&self.data, &mut self.cmsg_buf, buf)
    }

    fn send(&mut self, buf: &[u8], dest: SocketAddr, src: IpAddr) -> io::Result<usize> {
        send_impl(&self.data, buf, dest, src)
    }
}

////////////////////////////////////////////////////////////////////////
// ASYNCHRONOUS UDP SOCKETS WITH TOKIO                                //
////////////////////////////////////////////////////////////////////////

#[cfg(feature = "tokio")]
mod tokio {
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::task::{ready, Context, Poll};

    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use tokio::io::unix::AsyncFd;

    use super::super::AsyncUdpSocketApi;
    use super::UdpSocketSharedData;

    /// A Tokio-based asynchronous UDP socket implementation, available
    /// on Linux, NetBSD, and FreeBSD systems, with local address
    /// selection support.
    pub struct AsyncUdpSocket {
        data: Arc<AsyncFd<UdpSocketSharedData>>,
        cmsg_buf: Vec<u8>,
    }

    impl Clone for AsyncUdpSocket {
        fn clone(&self) -> Self {
            // See the note above in UdpSocket::clone; it also applies
            // here.
            Self {
                data: self.data.clone(),
                cmsg_buf: super::make_cmsg_buf(self.data.get_ref().bind_addr),
            }
        }
    }

    impl AsyncUdpSocketApi for AsyncUdpSocket {
        fn bind(addr: SocketAddr) -> io::Result<Self> {
            let (data, cmsg_buf) = super::bind_impl(addr)?;
            fcntl(data.fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            Ok(Self {
                data: Arc::new(AsyncFd::new(data)?),
                cmsg_buf,
            })
        }

        fn poll_recv(
            &mut self,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr, IpAddr)>> {
            loop {
                let mut guard = ready!(self.data.poll_read_ready(cx))?;
                match guard.try_io(|async_fd| {
                    super::recv_impl(async_fd.get_ref(), &mut self.cmsg_buf, buf)
                }) {
                    Ok(res) => return Poll::Ready(res),
                    Err(_) => continue,
                }
            }
        }

        fn poll_send(
            &mut self,
            cx: &mut Context<'_>,
            buf: &[u8],
            dest: SocketAddr,
            src: IpAddr,
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.data.poll_write_ready(cx))?;
                match guard.try_io(|async_fd| super::send_impl(async_fd.get_ref(), buf, dest, src))
                {
                    Ok(res) => return Poll::Ready(res),
                    Err(_) => continue,
                }
            }
        }
    }
}

#[cfg(feature = "tokio")]
pub use self::tokio::AsyncUdpSocket;

////////////////////////////////////////////////////////////////////////
// COMMON IMPLEMENTATION                                              //
////////////////////////////////////////////////////////////////////////

/// The common implementation for binding a UDP socket.
fn bind_impl(addr: SocketAddr) -> io::Result<(UdpSocketSharedData, Vec<u8>)> {
    // Create the socket.
    let family = if addr.is_ipv6() {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let fd = socket(
        family,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::Udp,
    )?;

    // For sockets bound to any local address, set the appropriate
    // socket option so that we receive the destination address used
    // to reach us when we call recvmsg.
    if addr.ip().is_unspecified() {
        let set_recv_dest_addr_sockopt_result = if addr.is_ipv6() {
            setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &true)
        } else {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "netbsd"))] {
                    setsockopt(fd, sockopt::Ipv4PacketInfo, &true)
                } else if #[cfg(target_os = "freebsd")] {
                    setsockopt(fd, sockopt::Ipv4RecvDstAddr, &true)
                }
            }
        };
        if let Err(e) = set_recv_dest_addr_sockopt_result {
            let _ = close(fd);
            return Err(e.into());
        }
    }

    // Bind the socket.
    let sock_addr = SockaddrStorage::from(addr);
    if let Err(e) = bind(fd, &sock_addr) {
        let _ = close(fd);
        return Err(e.into());
    }

    Ok((
        UdpSocketSharedData {
            fd,
            bind_addr: addr.ip(),
        },
        make_cmsg_buf(addr.ip()),
    ))
}

/// The common implementation for receiving a UDP packet.
fn recv_impl(
    data: &UdpSocketSharedData,
    cmsg_buf: &mut Vec<u8>,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let (msg, dest_addr) = if data.bind_addr.is_unspecified() {
        let msg: RecvMsg<SockaddrStorage> =
            recvmsg(data.fd, &mut iov, Some(cmsg_buf), MsgFlags::empty())?;
        let dest_addr = extract_dest_addr(data.bind_addr.is_ipv6(), msg.cmsgs())?;
        (msg, dest_addr)
    } else {
        let msg: RecvMsg<SockaddrStorage> = recvmsg(data.fd, &mut iov, None, MsgFlags::empty())?;
        (msg, data.bind_addr)
    };
    let src_addr = extract_src_addr(data.bind_addr.is_ipv6(), msg.address.as_ref())?;
    Ok((msg.bytes, src_addr, dest_addr))
}

/// The common implementation for sending a UDP packet.
fn send_impl(
    data: &UdpSocketSharedData,
    buf: &[u8],
    dest: SocketAddr,
    src: IpAddr,
) -> io::Result<usize> {
    let iov = [IoSlice::new(buf)];
    let dest_sockaddr = SockaddrStorage::from(dest);
    if data.bind_addr.is_unspecified() {
        if data.bind_addr.is_ipv6() {
            let info = make_in6_pktinfo(src)?;
            let cmsgs = [ControlMessage::Ipv6PacketInfo(&info)];
            sendmsg(
                data.fd,
                &iov,
                &cmsgs,
                MsgFlags::empty(),
                Some(&dest_sockaddr),
            )
            .map_err(Into::into)
        } else {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "netbsd"))] {
                    let info = make_in_pktinfo(src)?;
                    let cmsgs = [ControlMessage::Ipv4PacketInfo(&info)];
                } else if #[cfg(target_os = "freebsd")] {
                    let src_in_addr = make_in_addr(src)?;
                    let cmsgs = [ControlMessage::Ipv4SendSrcAddr(&src_in_addr)];
                }
            }
            sendmsg(
                data.fd,
                &iov,
                &cmsgs,
                MsgFlags::empty(),
                Some(&dest_sockaddr),
            )
            .map_err(Into::into)
        }
    } else if src == data.bind_addr {
        sendmsg(data.fd, &iov, &[], MsgFlags::empty(), Some(&dest_sockaddr)).map_err(Into::into)
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            "passed the wrong source address",
        ))
    }
}

/// Makes the control message buffer for a UDP socket. This
/// pre-allocates a buffer using [`cmsg_space`] when the address is
/// unspecified. For other addresses, the buffer will not be used, so an
/// empty [`Vec`] is returned.
fn make_cmsg_buf(addr: IpAddr) -> Vec<u8> {
    if !addr.is_unspecified() {
        Vec::new()
    } else if addr.is_ipv6() {
        cmsg_space!(in6_pktinfo)
    } else {
        cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "netbsd"))] {
                cmsg_space!(in_pktinfo)
            } else if #[cfg(target_os = "freebsd")] {
                cmsg_space!(in_addr)
            }
        }
    }
}

/// Converts the source address provided by `recvmsg` into the
/// a Rust [`SocketAddr`].
fn extract_src_addr(ipv6: bool, raw_opt: Option<&SockaddrStorage>) -> io::Result<SocketAddr> {
    if ipv6 {
        let raw = raw_opt.ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                "recvmsg did not return the source address",
            )
        })?;
        let raw6 = raw.as_sockaddr_in6().ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                "recvmsg did not return an IPv6 source address",
            )
        })?;
        Ok(SocketAddr::V6(SocketAddrV6::from(*raw6)))
    } else {
        let raw = raw_opt.ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                "recvmsg did not return the source address",
            )
        })?;
        let raw4 = raw.as_sockaddr_in().ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                "recvmsg did not return an IPv4 source address",
            )
        })?;
        Ok(SocketAddr::V4(SocketAddrV4::from(*raw4)))
    }
}

/// Finds the control message from `recvmsg` with the local destination
/// address and converts the information into a Rust [`IpAddr`].
fn extract_dest_addr(ipv6: bool, cmsgs: CmsgIterator) -> io::Result<IpAddr> {
    for cmsg in cmsgs {
        if ipv6 {
            if let ControlMessageOwned::Ipv6PacketInfo(info) = cmsg {
                return Ok(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
            }
        } else {
            #[cfg(any(target_os = "linux", target_os = "netbsd"))]
            if let ControlMessageOwned::Ipv4PacketInfo(info) = cmsg {
                return Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))));
            }
            #[cfg(target_os = "freebsd")]
            if let ControlMessageOwned::Ipv4RecvDstAddr(addr) = cmsg {
                return Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.s_addr))));
            }
        }
    }
    Err(Error::new(
        ErrorKind::Other,
        "recvmsg did not return the local destination address",
    ))
}

/// Converts a Rust [`IpAddr`] into an [`in6_pktinfo`].
fn make_in6_pktinfo(src: IpAddr) -> io::Result<in6_pktinfo> {
    match src {
        IpAddr::V6(src) => Ok(in6_pktinfo {
            ipi6_addr: in6_addr {
                s6_addr: src.octets(),
            },
            ipi6_ifindex: 0,
        }),
        IpAddr::V4(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            "passed an IPv4 source address to an IPv6 socket",
        )),
    }
}

/// Converts a Rust [`IpAddr`] into an [`in_pktinfo`].
#[cfg(any(target_os = "linux", target_os = "netbsd"))]
fn make_in_pktinfo(src: IpAddr) -> io::Result<in_pktinfo> {
    match src {
        #[cfg(target_os = "linux")]
        IpAddr::V4(src) => Ok(in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: in_addr {
                s_addr: u32::from(src).to_be(),
            },
            ipi_addr: in_addr { s_addr: 0 },
        }),
        #[cfg(target_os = "netbsd")]
        IpAddr::V4(src) => Ok(in_pktinfo {
            ipi_ifindex: 0,
            ipi_addr: in_addr {
                s_addr: u32::from(src).to_be(),
            },
        }),
        IpAddr::V6(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            "passed an IPv6 source address to an IPv4 socket",
        )),
    }
}

/// Converts a Rust [`IpAddr`] into an [`in_addr`].
#[cfg(target_os = "freebsd")]
fn make_in_addr(src: IpAddr) -> io::Result<in_addr> {
    match src {
        IpAddr::V4(src) => Ok(in_addr {
            s_addr: u32::from(src).to_be(),
        }),
        IpAddr::V6(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            "passed an IPv6 source address to an IPv4 socket",
        )),
    }
}
