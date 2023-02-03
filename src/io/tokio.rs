// Copyright 2023 Matthew Ingwersen.
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

//! Implementation of the Tokio I/O provider.

// NOTE: In this provider, I/O error handling is generally to exit the
// task. The run_with_respawning function acts as a supervisor that will
// respawn the TCP acceptor and UDP receivers, possibly after a delay,
// if they exit with an error or a panic.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

use crate::db::Catalog;
use crate::server::{ReceivedInfo, Response, Server, Transport};

use super::socket::{AsyncUdpSocket, AsyncUdpSocketApi};

/// A Tokio I/O provider.
///
/// This provider uses asynchronous I/O and runs the server by spawning
/// tasks on a Tokio runtime. This is a cross-platform provider: it
/// should work on any target that supports the required Tokio features.
///
/// The `TokioIoProvider` supports graceful shutdown. To initiate a
/// graceful shutdown, use the [`TokioShutdownController`] returned by
/// [`TokioIoProvider::start`].
pub struct TokioIoProvider {
    tcp_listeners: Vec<TcpListener>,
    udp_sockets: Vec<AsyncUdpSocket>,
}

impl TokioIoProvider {
    /// Creates a new `TokioIoProvider`. This call binds TCP and UDP
    /// sockets in preparation, but does not start the server. This
    /// function requires that the Tokio runtime be active.
    pub async fn bind<T, U>(tcp_addrs: T, udp_addrs: U) -> io::Result<Self>
    where
        T: IntoIterator<Item = SocketAddr>,
        U: IntoIterator<Item = SocketAddr>,
    {
        let mut tcp_listeners = Vec::new();
        for addr in tcp_addrs {
            let listener = TcpListener::bind(addr).await?;
            tcp_listeners.push(listener);
        }

        let mut udp_sockets = Vec::new();
        for addr in udp_addrs {
            let socket = AsyncUdpSocket::bind(addr)?;
            udp_sockets.push(socket);
        }

        Ok(Self {
            tcp_listeners,
            udp_sockets,
        })
    }

    /// Starts the server on the active Tokio runtime.
    ///
    /// This spawns tasks on the active Tokio runtime and then returns
    /// a [`TokioShutdownController`] that can be used to shut down the
    /// tasks at a later time. (The [`TokioShutdownController`] must be
    /// held as long as the server should be running, since dropping it
    /// will trigger shutdown.)
    pub fn start<C>(self, server: &Arc<Server<C>>) -> TokioShutdownController
    where
        C: Catalog + Send + Sync + 'static,
    {
        let (shutdown_controller, shutdown_handle) = make_shutdown_channels();

        // Start the TCP tasks.
        for tcp_listener in self.tcp_listeners {
            let shutdown_handle = shutdown_handle.clone();
            let server = server.clone();
            let tcp_listener = Arc::new(tcp_listener);
            tokio::spawn(run_with_respawning(
                run_tcp_listener,
                shutdown_handle,
                server,
                tcp_listener,
            ));
        }

        // Start the UDP tasks.
        for udp_socket in self.udp_sockets {
            let shutdown_handle = shutdown_handle.clone();
            let server = server.clone();
            tokio::spawn(run_with_respawning(
                run_udp_receiver,
                shutdown_handle,
                server,
                udp_socket,
            ));
        }

        shutdown_controller
    }
}

/// How long to wait between respawns of a task. This is to prevent
/// tasks that crash immediately from using up significant CPU time.
const TASK_RESPAWN_DELAY: Duration = Duration::from_secs(1);

/// Runs a Tokio task, respawning it if it returns an I/O error, is
/// cancelled, or panics.
async fn run_with_respawning<F, G, C, S>(
    f: F,
    mut shutdown: ShutdownHandle,
    server: Arc<Server<C>>,
    socket: S,
) where
    F: Fn(ShutdownHandle, Arc<Server<C>>, S) -> G,
    G: Future<Output = io::Result<()>> + Send + 'static,
    S: Clone,
{
    loop {
        let last_spawn_time = Instant::now();
        match tokio::spawn(f(shutdown.clone(), server.clone(), socket.clone())).await {
            Ok(Ok(())) => return,
            Ok(Err(e)) => log_io_error(e),
            Err(_) => (), // The task panicked or was cancelled.
        }

        // If necessary, wait before respawning, but receive shutdown
        // requests immediately.
        let since_last_spawn = Instant::now().duration_since(last_spawn_time);
        if let Some(duration_to_wait) = TASK_RESPAWN_DELAY.checked_sub(since_last_spawn) {
            tokio::select! {
                _ = shutdown.request_receiver.recv() => return,
                _ = tokio::time::sleep(duration_to_wait) => (),
            }
        }
    }
}

/// The TCP listener/accept loop.
async fn run_tcp_listener<C>(
    mut shutdown: ShutdownHandle,
    server: Arc<Server<C>>,
    listener: Arc<TcpListener>,
) -> io::Result<()>
where
    C: Catalog + Send + Sync + 'static,
{
    loop {
        let (client, client_socket_addr) = tokio::select! {
            _ = shutdown.request_receiver.recv() => return Ok(()),
            res = listener.accept() => res?,
        };
        let shutdown = shutdown.clone();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_connection(shutdown, &server, client, client_socket_addr.ip()).await
            {
                log_io_error(e);
            }
        });
    }
}

/// Handles a TCP connection.
async fn handle_tcp_connection<C>(
    mut shutdown: ShutdownHandle,
    server: &Server<C>,
    mut socket: TcpStream,
    client_ip: IpAddr,
) -> io::Result<()>
where
    C: Catalog + Send,
{
    let mut received_buf = vec![0; 2 + u16::MAX as usize];
    let mut response_buf = vec![0; 2 + u16::MAX as usize];
    let mut n_read = 0;

    loop {
        let received_len = match timeout(
            super::READ_MESSAGE_TIMEOUT,
            read_message_over_tcp(&mut socket, &mut received_buf, &mut n_read),
        )
        .await
        {
            Ok(Ok(Some(len))) => len,
            Ok(Ok(None)) => return Ok(()), // The connection was closed.
            Ok(Err(e)) => return Err(e),   // There was an I/O error.
            Err(_) => return Ok(()),       // The operation timed out.
        };

        // Process the DNS message and write the response, if any.
        match server.handle_message(
            &received_buf[2..received_len + 2],
            ReceivedInfo::new(client_ip, Transport::Tcp),
            &mut response_buf[2..],
        ) {
            Response::Single(response_len) => {
                response_buf[0..2].copy_from_slice(&u16::to_be_bytes(response_len as u16));
                socket.write_all(&response_buf[0..2 + response_len]).await?;
            }

            // Response::None occurs when something was really
            // malformed, so close the connection.
            Response::None => return Ok(()),
        };

        // We won't continue to service this connection if we are
        // shutting down.
        if matches!(
            shutdown.request_receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Closed)
        ) {
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

/// Reads a single DNS message (including the initial two-octet length
/// field) from a [`TcpStream`].
///
/// This function assumes that `*n_read` octets have already been read
/// into the buffer. It updates `*n_read` as it reads more data. It may
/// read data past the end of the message. When this function returns,
/// `*n_read` reflects the number of octets read into the buffer
/// (including the initial two-octet length field and any data read
/// after the end of the message), while the returned `usize` (if any)
/// is the size of the message itself (not including the initial length
/// field).
///
/// If this function returns `Ok(None)`, then the connection was closed
/// before a whole message could be read.
async fn read_message_over_tcp(
    socket: &mut TcpStream,
    buf: &mut [u8],
    n_read: &mut usize,
) -> io::Result<Option<usize>> {
    // This implementation is adapted from the blocking I/O provider;
    // see the notes there. The biggest difference here is that we don't
    // need to deal with timeouts.
    let mut received_len_opt = None;
    loop {
        // There may already be data in the buffer. (See the notes in
        // the blocking implementation.)
        if let Some(received_len) = received_len_opt {
            if *n_read >= received_len + 2 {
                return Ok(Some(received_len));
            }
        } else if *n_read >= 2 {
            // We've got the first two octets, so we now know the
            // message length.
            let received_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if *n_read >= received_len + 2 {
                return Ok(Some(received_len));
            } else {
                received_len_opt = Some(received_len);
            }
        }

        // Do the next read.
        let n_read_this_time = socket.read(&mut buf[*n_read..]).await?;

        // If we read nothing, then the client closed their side of
        // the connection.
        if n_read_this_time == 0 {
            return Ok(None);
        }

        // Prepare for the next iteration.
        *n_read += n_read_this_time;
    }
}

/// The UDP receiver loop.
async fn run_udp_receiver<C>(
    mut shutdown: ShutdownHandle,
    server: Arc<Server<C>>,
    mut socket: AsyncUdpSocket,
) -> io::Result<()>
where
    C: Catalog + Send + Sync + 'static,
{
    let udp_payload_size = server.edns_udp_payload_size() as usize;

    loop {
        let mut received_buf = vec![0; udp_payload_size];
        let mut response_buf = vec![0; udp_payload_size];

        // Receive a DNS message (or a shutdown request).
        let (received_len, src, dest) = tokio::select! {
            _ = shutdown.request_receiver.recv() => return Ok(()),
            res = socket.recv(&mut received_buf) => res?,
        };

        // In a new Tokio task, process the DNS message and send the
        // response (if any).
        let shutdown = shutdown.wait_sender.clone();
        let server = server.clone();
        let mut socket = socket.clone();
        tokio::spawn(async move {
            match server.handle_message(
                &received_buf[0..received_len],
                ReceivedInfo::new(src.ip(), Transport::Udp),
                &mut response_buf,
            ) {
                Response::Single(response_len) => {
                    if let Err(e) = socket.send(&response_buf[0..response_len], src, dest).await {
                        log_io_error(e);
                    }
                }
                Response::None => (),
            }

            // This ensures that the shutdown handle is moved into the
            // new task.
            drop(shutdown);
        });
    }
}

/// Controls the shutdown of a server's Tokio tasks.
///
/// This type is used to shut down the Tokio tasks spawned by
/// [`TokioIoProvider::start`]. Use
/// [`TokioShutdownController::shut_down`] or its blocking variant,
/// [`TokioShutdownController::blocking_shut_down`], to initiate
/// shutdown and wait for its completion. Dropping the controller will
/// also trigger shutdown (but will not wait for it to complete).
#[must_use]
pub struct TokioShutdownController {
    request_sender: broadcast::Sender<()>,
    wait_receiver: mpsc::Receiver<()>,
}

impl TokioShutdownController {
    /// Requests that running server tasks shut down, and then waits for
    /// them to terminate.
    pub async fn shut_down(mut self) {
        drop(self.request_sender);
        let _ = self.wait_receiver.recv().await;
    }

    /// The blocking variant of [`TokioShutdownController::shut_down`].
    pub fn blocking_shut_down(mut self) {
        drop(self.request_sender);
        let _ = self.wait_receiver.blocking_recv();
    }
}

/// A handle held by tasks to interact with the graceful shutdown
/// mechanism.
///
/// This type has two roles:
///
/// 1. It enables tasks to listen for graceful shutdown signals. This
///    is done by waiting for all senders attached to `request_receiver`
///    to close.
/// 2. It prevents graceful shutdown from completing until it is
///    dropped. This is done by holding `wait_sender`. All server tasks
///    therefore own a `ShutdownHandle` (or at least the `wait_sender`
///    component).
struct ShutdownHandle {
    request_receiver: broadcast::Receiver<()>,
    wait_sender: mpsc::Sender<()>,
}

impl Clone for ShutdownHandle {
    fn clone(&self) -> Self {
        // When a broadcast receiver is created through the resubscribe
        // method, the new receiver does not receive any values already
        // in the original receiver's queue. However, missing values are
        // not an issue in our case. The shutdown signal is not a value
        // being sent, but rather all senders being dropped.
        ShutdownHandle {
            request_receiver: self.request_receiver.resubscribe(),
            wait_sender: self.wait_sender.clone(),
        }
    }
}

/// Produces a [`TokioShutdownController`] and an initial
/// [`ShutdownHandle`] connected to it.
fn make_shutdown_channels() -> (TokioShutdownController, ShutdownHandle) {
    let (request_sender, request_receiver) = broadcast::channel(1);
    let (wait_sender, wait_receiver) = mpsc::channel(1);
    let controller = TokioShutdownController {
        request_sender,
        wait_receiver,
    };
    let handle = ShutdownHandle {
        request_receiver,
        wait_sender,
    };
    (controller, handle)
}

/// Logs an I/O error.
fn log_io_error(e: io::Error) {
    // TODO: Tokio has unstable support for task names. If it's
    // stabilized, set them and include them in the output here.
    error!("I/O error: {e}");
}
