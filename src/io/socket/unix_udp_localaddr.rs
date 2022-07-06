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
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::time::Duration;

use libc::{in6_addr, in6_pktinfo, in_addr, in_pktinfo};
use nix::cmsg_space;
use nix::sys::socket::{
    bind, recvmsg, sendmsg, setsockopt, socket, sockopt, AddressFamily, CmsgIterator,
    ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SockFlag, SockProtocol, SockType,
    SockaddrStorage,
};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::close;

use super::UdpSocketApi;

/// A UDP socket implementation for Unix systems with local address
/// selection support. This currently works on Linux and NetBSD.
pub struct UdpSocket {
    data: Arc<UdpSocketSharedData>,
    cmsg_buf: Vec<u8>,
}

/// Each [`UdpSocket`] corresponding to a single file descriptor has its
/// own control-message buffer, but they all share a copy of this
/// structure through an [`Arc`] smart pointer. This type's [`Drop`]
/// implementation closes the socket file descriptor.
#[derive(Clone)]
struct UdpSocketSharedData {
    fd: RawFd,
    ipv6: bool,
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
            cmsg_buf: make_cmsg_buf(self.data.ipv6),
        }
    }
}

impl Drop for UdpSocketSharedData {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

impl UdpSocketApi for UdpSocket {
    type LocalAddr = IpAddr;
    const SUPPORTS_LOCAL_ADDRESS_SELECTION: bool = true;

    fn bind(addr: SocketAddr) -> io::Result<Self> {
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

        // Set the appropriate socket option so that we receive the
        // destination address used to reach us when we call
        // recvmsg.
        let set_recv_dest_addr_sockopt_result = if addr.is_ipv6() {
            setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &true)
        } else {
            #[cfg(any(target_os = "linux", target_os = "netbsd"))]
            setsockopt(fd, sockopt::Ipv4PacketInfo, &true)
        };
        if let Err(e) = set_recv_dest_addr_sockopt_result {
            let _ = close(fd);
            return Err(e.into());
        }

        // Bind the socket.
        let sock_addr = SockaddrStorage::from(addr);
        if let Err(e) = bind(fd, &sock_addr) {
            let _ = close(fd);
            return Err(e.into());
        }

        // Allocate space for the control message buffer that we will
        // use when receiving.
        let cmsg_buf = make_cmsg_buf(addr.is_ipv6());

        Ok(Self {
            data: Arc::new(UdpSocketSharedData {
                fd,
                ipv6: addr.is_ipv6(),
            }),
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
        let mut iov = [IoSliceMut::new(buf)];
        let msg: RecvMsg<SockaddrStorage> = recvmsg(
            self.data.fd,
            &mut iov,
            Some(&mut self.cmsg_buf),
            MsgFlags::empty(),
        )?;
        let src_addr = extract_src_addr(self.data.ipv6, msg.address.as_ref())?;
        let dest_addr = extract_dest_addr(self.data.ipv6, msg.cmsgs())?;
        Ok((msg.bytes, src_addr, dest_addr))
    }

    fn send(&mut self, buf: &[u8], dest: SocketAddr, src: IpAddr) -> io::Result<usize> {
        let iov = [IoSlice::new(buf)];
        let dest_sockaddr = SockaddrStorage::from(dest);
        if self.data.ipv6 {
            let info = make_in6_pktinfo(src)?;
            let cmsgs = [ControlMessage::Ipv6PacketInfo(&info)];
            sendmsg(
                self.data.fd,
                &iov,
                &cmsgs,
                MsgFlags::empty(),
                Some(&dest_sockaddr),
            )
            .map_err(Into::into)
        } else {
            let info = make_in_pktinfo(src)?;
            let cmsgs = [ControlMessage::Ipv4PacketInfo(&info)];
            sendmsg(
                self.data.fd,
                &iov,
                &cmsgs,
                MsgFlags::empty(),
                Some(&dest_sockaddr),
            )
            .map_err(Into::into)
        }
    }
}

/// Allocates the control message buffer for a UDP socket.
fn make_cmsg_buf(ipv6: bool) -> Vec<u8> {
    if ipv6 {
        cmsg_space!(in6_pktinfo)
    } else {
        #[cfg(any(target_os = "linux", target_os = "netbsd"))]
        cmsg_space!(in_pktinfo)
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
        Ok(SocketAddr::V6(SocketAddrV6::new(
            raw6.ip(),
            raw6.port(),
            raw6.flowinfo(),
            raw6.scope_id(),
        )))
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
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(raw4.ip()),
            raw4.port(),
        )))
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
