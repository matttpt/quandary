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

//! Implementation of the blocking I/O provider.

// NOTE: In this provider, I/O error handling is generally to exit the
// task. For the TCP accept loop and UDP receive/send loop, this will
// cause the thread to respawn, possibly after a delay (if the last
// respawn occurred too recently); this prevents us from using up all
// CPU time on I/O operations that repeatedly fail. For the TCP
// connection handler, this aborts the connection on I/O error, as
// appropriate.
//
// The single exception is that *sends* in the UDP receive/send loop
// do not cause the task to exit, but are rather logged and ignored.
// Therefore we will keep processing incoming messages as long as the
// *receive* portion continues to work.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log::error;

use super::socket::{TcpListener, TcpListenerApi, UdpSocket, UdpSocketApi};
use crate::db::Catalog;
use crate::server::{ReceivedInfo, Response, Server, Transport};
use crate::thread::{ThreadGroup, ThreadPool};

/// A blocking I/O provider.
///
/// This provider uses blocking I/O to communicate over the network,
/// employing a configurable number of worker threads for concurrency.
/// This is a cross-platform provider: it gains extra features from
/// [target-specific socket support](`super::socket`), but it does not
/// require it.
///
/// # Target-specific features
///
/// The `BlockingIoProvider` supports graceful shutdown on targets with
/// `poll_accept` support ([see here](`super::socket`)). To initiate a
/// graceful shutdown, simply shut down the [`ThreadGroup`] in which the
/// provider was started (see [`BlockingIoProvider::start`]). Graceful
/// shutdown support can be probed by checking
/// [`BlockingIoProvider::SUPPORTS_GRACEFUL_SHUTDOWN`]. This feature is
/// currently available on **Unix** targets.
pub struct BlockingIoProvider {
    config: BlockingIoConfig,
    tcp_listeners: Vec<TcpListener>,
    udp_sockets: Vec<UdpSocket>,
}

/// Configuration options for the [`BlockingIoProvider`].
pub struct BlockingIoConfig {
    /// The base number of TCP worker threads to maintain. If more than
    /// this many TCP connections are established, a temporary auxiliary
    /// thread will be spawned for each additional connection.
    pub tcp_base_workers: usize,

    /// How long auxiliary TCP worker threads will linger waiting for a
    /// new connection to serve before exiting.
    pub tcp_worker_linger: Duration,

    /// The number of UDP worker threads to run for each UDP socket.
    pub udp_workers_per_socket: usize,
}

impl BlockingIoProvider {
    /// Whether the `BlockingIoProvider` supports graceful shutdown on
    /// the target system.
    ///
    /// Implementing graceful shutdown requires us to time out if
    /// blocking to accept a TCP connection takes too long. This is not
    /// possible with the Rust standard library and requires
    /// target-specific support (see the description of `poll_accept`
    /// [here](`super::socket`)).
    pub const SUPPORTS_GRACEFUL_SHUTDOWN: bool = TcpListener::POLL_ACCEPT_WORKS;

    /// Creates a new `BlockingIoProvider`. This call binds TCP and UDP
    /// sockets in preparation, but does not start the server.
    pub fn bind<T, U>(config: BlockingIoConfig, tcp_addrs: T, udp_addrs: U) -> io::Result<Self>
    where
        T: IntoIterator<Item = SocketAddr>,
        U: IntoIterator<Item = SocketAddr>,
    {
        let mut tcp_listeners = Vec::new();
        for addr in tcp_addrs {
            let listener = TcpListener::bind(addr)?;
            if TcpListener::POLL_ACCEPT_WORKS {
                listener.set_nonblocking(true)?;
            }
            tcp_listeners.push(listener);
        }

        let mut udp_sockets = Vec::new();
        for addr in udp_addrs {
            let socket = UdpSocket::bind(addr)?;
            socket.set_read_timeout(Some(CHECK_FOR_SHUTDOWN_TIMEOUT))?;
            udp_sockets.push(socket);
        }

        Ok(Self {
            config,
            tcp_listeners,
            udp_sockets,
        })
    }

    /// Starts the server on the provided [`ThreadGroup`].
    ///
    /// On platforms with graceful shutdown support, the server can be
    /// shut down later simply by shutting down the [`ThreadGroup`]
    /// provided here.
    pub fn start<C>(
        self,
        server: &Arc<Server<C>>,
        group: &Arc<ThreadGroup>,
    ) -> Result<(), crate::thread::Error>
    where
        C: Catalog + Send + Sync + 'static,
    {
        // Start the TCP threads.
        let tcp_workers = group.start_pool(
            Some("tcp".to_owned()),
            self.config.tcp_base_workers,
            self.config.tcp_worker_linger,
        )?;
        for (i, tcp_listener) in self.tcp_listeners.into_iter().enumerate() {
            let name = format!("tcp listener {i}");
            let tcp_workers = tcp_workers.clone();
            let server = server.clone();
            let task = move || {
                log_io_errors(run_tcp_listener(&tcp_workers, &server, &tcp_listener));
            };
            group.start_respawnable(Some(name), task)?;
        }

        // Start the UDP threads.
        for (i, udp_socket) in self.udp_sockets.into_iter().enumerate() {
            for j in 0..self.config.udp_workers_per_socket {
                let name = format!("udp worker {i}/{j}");
                let group_clone = group.clone();
                let server = server.clone();
                let udp_socket = udp_socket.clone();
                let task = move || {
                    log_io_errors(run_udp_worker(&group_clone, &server, udp_socket.clone()));
                };
                group.start_respawnable(Some(name), task)?;
            }
        }

        Ok(())
    }
}

/// This defines the timeout on TCP accept and UDP receive operations.
/// TCP listener and UDP worker threads check for thread group shutdown
/// between every accept and receive, respectively, so this defines the
/// *maximum* interval between such checks. Consequently, it is the
/// maximum amount of time the shutdown procedure will have to wait for
/// these threads to finish up.
///
/// Note that for this functionality to work, we must support it on the
/// target platform. See
/// [`BlockingIoProvider::SUPPORTS_GRACEFUL_SHUTDOWN`].
const CHECK_FOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// This defines the maximum amount of time a client is allowed to take
/// to send us a full DNS message. If it it takes longer, we close the
/// connection to defend against Slowloris-style denial-of-service
/// attacks. Since TCP workers check for shutdown after handling a
/// message, this (plus message processing time) is the maximum amount
/// of time the shutdown procedure will have to wait for these threads
/// to finish up.
const READ_MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The TCP listener/accept loop.
fn run_tcp_listener<C>(
    pool: &Arc<ThreadPool>,
    server: &Arc<Server<C>>,
    listener: &TcpListener,
) -> io::Result<()>
where
    C: Catalog + Send + Sync + 'static,
{
    loop {
        if pool.is_shutting_down() {
            return Ok(());
        }

        // Note that poll_accept returns false if interrupted. If
        // poll_accept doesn't work on this platform, then this always
        // returns true immediately.
        let ready = listener.poll_accept(CHECK_FOR_SHUTDOWN_TIMEOUT)?;
        if ready {
            // Accept as many new connections as are available. If
            // poll_accept doesn't work on this platform, then the
            // accept call blocks (since in this case we didn't enable
            // nonblocking mode in BlockingIoProvider::bind).
            loop {
                let (client, client_ip) = match retry_if_interrupted(|| listener.accept()) {
                    Ok((client, socket_addr)) => (client, socket_addr.ip()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                };
                let pool_clone = pool.clone();
                let server = server.clone();
                let task = move || {
                    log_io_errors(handle_tcp_connection(
                        &pool_clone,
                        &server,
                        client,
                        client_ip,
                    ));
                };
                match pool.submit_or_spawn(task) {
                    Ok(()) => (),
                    Err(crate::thread::Error::ShuttingDown) => {
                        // Let the connection close.
                        return Ok(());
                    }
                    Err(crate::thread::Error::Io(e)) => return Err(e),
                }
            }
        }
    }
}

/// Handles a TCP connection.
fn handle_tcp_connection<C>(
    pool: &Arc<ThreadPool>,
    server: &Arc<Server<C>>,
    mut socket: TcpStream,
    client_ip: IpAddr,
) -> io::Result<()>
where
    C: Catalog + Send,
{
    if TcpListener::POLL_ACCEPT_WORKS {
        // On some systems, the socket might inherit nonblocking status
        // from the listener.
        socket.set_nonblocking(false)?;
    }

    let mut received_buf = vec![0; 2 + u16::MAX as usize];
    let mut response_buf = vec![0; 2 + u16::MAX as usize];
    let mut n_read = 0;

    loop {
        // We give the client READ_MESSAGE_TIMEOUT to send a complete
        // DNS message. This counters Slowloris-style denial-of-service
        // attacks.
        let deadline = Instant::now() + READ_MESSAGE_TIMEOUT;
        let mut timeout = READ_MESSAGE_TIMEOUT;

        // Read a DNS message.
        let mut received_len_opt = None;
        let received_len = loop {
            // We start by seeing whether we have read an entire
            // message, or, barring that, whether we have read the two
            // octets preceding the next message (which give its
            // length). This must be done before reading more data from
            // the network: if a client pipelines messages, we may be
            // starting the first iteration of this loop with data
            // (possibly even a whole message!) already in the buffer.
            if let Some(received_len) = received_len_opt {
                if n_read >= received_len + 2 {
                    break received_len;
                }
            } else if n_read >= 2 {
                // We've got the first two octets, so we now know the
                // message length.
                let received_len = u16::from_be_bytes([received_buf[0], received_buf[1]]) as usize;
                if n_read >= received_len + 2 {
                    break received_len;
                } else {
                    received_len_opt = Some(received_len);
                }
            }

            // Do the next read, closing the connection if it times out.
            socket.set_read_timeout(Some(timeout))?;
            let n_read_this_time = match socket.read(&mut received_buf[n_read..]) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    timeout = match compute_timeout(deadline) {
                        Some(t) => t,
                        None => return Ok(()),
                    };
                    continue;
                }
                Err(e) => return Err(e),
            };

            // If we read nothing, then the client closed their side of
            // the connection.
            if n_read_this_time == 0 {
                return Ok(());
            }

            // Prepare for the next iteration.
            n_read += n_read_this_time;
            timeout = match compute_timeout(deadline) {
                Some(t) => t,
                None => return Ok(()),
            }
        };

        // Process the DNS message and write the response, if any.
        match server.handle_message(
            &received_buf[2..received_len + 2],
            ReceivedInfo::new(client_ip, Transport::Tcp),
            &mut response_buf[2..],
        ) {
            Response::Single(response_len) => {
                // Note that write_all retries if the write system calls
                // are interrupted.
                response_buf[0..2].copy_from_slice(&u16::to_be_bytes(response_len as u16));
                socket.write_all(&response_buf[0..2 + response_len])?;
            }

            // Response::None occurs when something was really
            // malformed, so close the connection.
            Response::None => return Ok(()),
        };

        // We won't continue to service this connection if the TCP
        // worker pool is shutting down.
        if pool.is_shutting_down() {
            return Ok(());
        }

        // Any leftover data is the start of the next message.
        if n_read > received_len + 2 {
            received_buf.copy_within(received_len + 2..n_read, 0);
            n_read -= received_len + 2;
        } else {
            n_read = 0;
        }
    }
}

/// The UDP receive/handle/send loop.
fn run_udp_worker<C>(
    group: &Arc<ThreadGroup>,
    server: &Arc<Server<C>>,
    mut socket: UdpSocket,
) -> io::Result<()>
where
    C: Catalog,
{
    let udp_payload_size = server.edns_udp_payload_size() as usize;
    let mut received_buf = vec![0; udp_payload_size];
    let mut response_buf = vec![0; udp_payload_size];

    loop {
        if group.is_shutting_down() {
            return Ok(());
        }

        // Receive a DNS message. If interrupted, we skip the rest of
        // the loop body and check whether the group is shutting down
        // again before retrying. Otherwise, repeated interruptions
        // could in theory prevent the call from ever timing out.
        let (received_len, src, dest) = match socket.recv(&mut received_buf) {
            Ok(tuple) => tuple,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        // Process the DNS message and send the response, if any.
        match server.handle_message(
            &received_buf[0..received_len],
            ReceivedInfo::new(src.ip(), Transport::Udp),
            &mut response_buf,
        ) {
            Response::Single(response_len) => {
                // Don't exit the task if the send fails. (See the note
                // at the beginning of the module.)
                log_io_errors(retry_if_interrupted(|| {
                    socket.send(&response_buf[0..response_len], src, dest)
                }));
            }
            Response::None => (),
        }
    }
}

/// Computes the time until the deadline. Returns [`None`] if the
/// deadline is in the past.
fn compute_timeout(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now())
}

/// Executes `f`, retrying the operation if it is interrupted.
fn retry_if_interrupted<F, R>(mut f: F) -> io::Result<R>
where
    F: FnMut() -> io::Result<R>,
{
    loop {
        match f() {
            Ok(r) => return Ok(r),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Logs errors if a task exits with an I/O error.
fn log_io_errors<T>(result: io::Result<T>) {
    if let Err(e) = result {
        let current_thread = thread::current();
        let thread_name = current_thread.name().unwrap_or("anonymous thread");
        error!("I/O error in thread {}: {}", thread_name, e);
    }
}
