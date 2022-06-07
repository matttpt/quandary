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

//! Thread groups and thread pools.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::mem::drop;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use log::{error, info};
use slab::Slab;

////////////////////////////////////////////////////////////////////////
// THREAD GROUPS                                                      //
////////////////////////////////////////////////////////////////////////

/// A group of threads managed together.
///
/// A `ThreadGroup` manages the creation and operation of a number of
/// threads. It supports the creation of both one-shot threads
/// (see [`ThreadGroup::start_oneshot`]) and respawnable threads
/// (see [`ThreadGroup::start_respawnable`]).
///
/// Additionally, a `ThreadGroup` may have a number of child
/// [`ThreadPool`]s, which provide a fixed number of permanent worker
/// threads that can accept one-shot tasks. See
/// [`ThreadGroup::start_pool`].
///
/// A `ThreadGroup` may be shut down through [`ThreadGroup::shut_down`].
/// New threads cannot be started in a `ThreadGroup` once shutdown is
/// initiated, and any respawnable threads whose tasks exit or crash
/// will not be restarted once shutdown has begun.
/// [`ThreadGroup::await_shutdown`] can be used to wait for shutdown to
/// complete. This condition requires all threads to have exited.
/// Therefore, one might want to give long-running tasks executing in a
/// group an [`Arc`] reference to the `ThreadGroup` so that such tasks
/// can check for group shutdown ([`ThreadGroup::is_shutting_down`]) and
/// gracefully exit early if necessary.
pub struct ThreadGroup {
    records: Mutex<GroupRecords>,

    /// Allows threads to wait for group shutdown events. This is used
    /// with the `records` mutex. All waiting threads are notified when
    /// (1) shutdown is initiated and (2) shutdown is complete.
    shutdown_wakeup: Condvar,
}

/// The internal records of a [`ThreadGroup`].
#[derive(Default)]
struct GroupRecords {
    thread_count: usize,
    pools: Slab<Arc<ThreadPool>>,
    shutting_down: bool,
}

impl ThreadGroup {
    /// Creates a new thread group.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(GroupRecords::default()),
            shutdown_wakeup: Condvar::new(),
        })
    }

    /// Starts a one-shot thread in the `ThreadGroup`. This thread will
    /// execute `task` once. The task will not be restarted, even if the
    /// thread panics.
    pub fn start_oneshot<F>(self: &Arc<Self>, name: Option<String>, task: F) -> Result<(), Error>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut records = self.records.lock().unwrap();
        if records.shutting_down {
            Err(Error::ShuttingDown)
        } else {
            start_oneshot(self.clone(), &mut records, name, task).map_err(Into::into)
        }
    }

    /// Starts a respawnable thread in the `ThreadGroup`. The thread
    /// will execute `task`. If `task` exits or panics and the
    /// `ThreadGroup` is not shutting down, a new thread will be started
    /// to execute `task` again. A short delay between successive
    /// respawn attempts is enforced to prevent a crash loop from using
    /// excessive CPU time.
    pub fn start_respawnable<F>(
        self: &Arc<Self>,
        name: Option<String>,
        task: F,
    ) -> Result<(), Error>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut records = self.records.lock().unwrap();
        if records.shutting_down {
            Err(Error::ShuttingDown)
        } else {
            start_respawnable(self.clone(), &mut records, name, Arc::new(task)).map_err(Into::into)
        }
    }

    /// Shuts down the `ThreadGroup`. Note that this includes any
    /// [`ThreadPool`]s created in the group.
    pub fn shut_down(&self) {
        let mut records = self.records.lock().unwrap();
        records.shutting_down = true;
        for pool in records.pools.drain() {
            pool.shut_down_without_removing();
        }
        self.shutdown_wakeup.notify_all();
    }

    /// Waits for the `ThreadGroup` to shut down. This is defined as (1)
    /// shutdown having been initiated ([`ThreadGroup::shut_down`]) and
    /// (2) the thread count having dropped to zero. Note that if this
    /// is called from a thread within the group, a deadlock will occur
    /// (since the thread count will never become zero).
    pub fn await_shutdown(&self) {
        let records = self.records.lock().unwrap();
        let _guard = self
            .shutdown_wakeup
            .wait_while(records, |r| !r.shutting_down || r.thread_count > 0)
            .unwrap();
    }

    /// Returns whether the `ThreadGroup` is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.records.lock().unwrap().shutting_down
    }
}

/// A handle to be owned by a one-shot thread. When dropped (when the
/// thread exits or panics), it will perform necessary clean-up actions
/// (see [`end_thread`]).
struct OneshotHandle {
    group: Arc<ThreadGroup>,
    parent: ThreadId,
}

/// The implementation of one-shot thread creation.
fn start_oneshot<F>(
    group: Arc<ThreadGroup>,
    records: &mut MutexGuard<GroupRecords>,
    name: Option<String>,
    task: F,
) -> io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    records.thread_count += 1;
    let handle = OneshotHandle {
        group,
        parent: thread::current().id(),
    };
    let result = thread::Builder::new()
        .name(name.unwrap_or_else(|| "anonymous".to_owned()))
        .spawn(move || {
            task();
            drop(handle);
        });
    if result.is_err() {
        records.thread_count -= 1;
    }
    result.and(Ok(()))
}

impl Drop for OneshotHandle {
    fn drop(&mut self) {
        let current_thread = thread::current();

        // If we are being dropped in the parent thread, then the new
        // thread failed to start (on the OS level). In this case,
        // start_oneshot handles any necessary clean-up. This is
        // important, since otherwise we would be locking the records
        // mutex twice from the same thread!
        if current_thread.id() == self.parent {
            return;
        }

        if thread::panicking() {
            let thread_name = current_thread.name().unwrap_or("anonymous");
            error!("One-shot thread {} panicked", thread_name);
        }

        let mut records = self.group.records.lock().unwrap();
        end_thread(&mut records, &self.group.shutdown_wakeup);
    }
}

/// How long to wait between successive starts of a respawnable thread.
/// If a thread exits/panics within `THREAD_RESPAWN_DELAY` of its last
/// start, it will sleep long enough before spawning a new copy of
/// itself to maintain this delay. This is to prevent
/// immediately-crashing threads from using up significant CPU time.
const THREAD_RESPAWN_DELAY: Duration = Duration::from_secs(1);

/// A handle to be owned by a respawnable thread. When dropped (when the
/// thread exits or panics), it will perform necessary clean-up actions
/// (see [`end_thread`]). It will also, when appropriate, execute a
/// respawn.
struct RespawnableHandle<F>
where
    F: Fn() + Send + Sync + 'static,
{
    group: Arc<ThreadGroup>,
    parent: ThreadId,
    task: Arc<F>,
    last_start: Instant,
}

/// The implementation of respawnable thread creation.
fn start_respawnable<F>(
    group: Arc<ThreadGroup>,
    records: &mut MutexGuard<GroupRecords>,
    name: Option<String>,
    task: Arc<F>,
) -> io::Result<()>
where
    F: Fn() + Send + Sync + 'static,
{
    records.thread_count += 1;
    let handle = RespawnableHandle {
        group,
        parent: thread::current().id(),
        task,
        last_start: Instant::now(),
    };
    let result = thread::Builder::new()
        .name(name.unwrap_or_else(|| "anonymous".to_owned()))
        .spawn(move || {
            (handle.task)();
            drop(handle);
        });
    if result.is_err() {
        records.thread_count -= 1;
    }
    result.and(Ok(()))
}

impl<F> Drop for RespawnableHandle<F>
where
    F: Fn() + Send + Sync + 'static,
{
    fn drop(&mut self) {
        let current_thread = thread::current();
        let thread_name = current_thread.name().unwrap_or("anonymous");

        // See the note in OneshotHandle::drop; the same principle
        // applies. start_respawnable handles clean-up.
        if current_thread.id() == self.parent {
            return;
        }

        if thread::panicking() {
            error!("Respawnable thread {} panicked", thread_name);
        }

        let mut records = self.group.records.lock().unwrap();
        if !records.shutting_down {
            if !thread::panicking() {
                error!("Respawnable thread {} exited prematurely", thread_name);
            }

            let since_last_start = Instant::now().duration_since(self.last_start);
            if since_last_start < THREAD_RESPAWN_DELAY {
                // It's been less than THREAD_RESPAWN_DELAY since this
                // thread was last respawned, so we delay until that
                // period has elapsed. Note that we allow our delay to
                // be interrupted by notifications on the thread group's
                // wakeup condition variable. These occur when shutdown
                // is first initiated, and when shutdown is complete
                // (which actually should never happen, since as long as
                // this thread is alive, the thread count should be
                // non-zero). Either way, shutdown is occuring, so
                // there's no point in continuing the delay. Note that
                // this also releases the records mutex for the duration
                // of the delay.
                let wait_for = THREAD_RESPAWN_DELAY - since_last_start;
                info!(
                    "Respawn of thread {} throttled: delayed by {} ms",
                    thread_name,
                    wait_for.as_millis()
                );
                records = self
                    .group
                    .shutdown_wakeup
                    .wait_timeout(records, wait_for)
                    .unwrap()
                    .0;
            }

            // If (possibly after delaying) the thread pool is still not
            // shutting down, we respawn.
            if !records.shutting_down {
                let result = start_respawnable(
                    self.group.clone(),
                    &mut records,
                    Some(thread_name.to_owned()),
                    self.task.clone(),
                );
                if let Err(e) = result {
                    error!("Respawn of thread {} failed: {}", thread_name, e);
                }
            }
        }
        end_thread(&mut records, &self.group.shutdown_wakeup);
    }
}

/// Performs clean-up actions when a thread exits.
fn end_thread(records: &mut MutexGuard<GroupRecords>, shutdown_wakeup: &Condvar) {
    records.thread_count -= 1;
    if records.shutting_down && records.thread_count == 0 {
        shutdown_wakeup.notify_all();
    }
}

////////////////////////////////////////////////////////////////////////
// THREAD POOLS                                                       //
////////////////////////////////////////////////////////////////////////

/// A thread pool that provides a fixed number of permanent worker
/// threads on which to execute tasks.
///
/// A `ThreadPool` is always created within a [`ThreadGroup`] through
/// [`ThreadGroup::start_pool`].
///
/// Queueing an arbitrary number of tasks is not supported. There are
/// thus two ways of submitting tasks to the pool, depending on whether
/// it is preferable to block until a permanent worker is available
/// ([`ThreadPool::submit`]) or to start an auxiliary worker thread
/// ([`ThreadPool::submit_or_spawn`]).
///
/// A `ThreadPool` is shut down if its parent [`ThreadGroup`] is shut
/// down. Furthermore, it may be independently shut down through
/// [`ThreadPool::shut_down`]. No new task submissions are allowed after
/// shutdown is initiated.
pub struct ThreadPool {
    group: Arc<ThreadGroup>,
    key: usize,
    name: String,
    records: Mutex<PoolRecords>,

    /// Allows permanent worker threads to wait for new tasks. Used with
    /// the `records` mutex.
    task_wakeup: Condvar,

    /// Allows submitting threads to wait for an available permanent
    /// worker thread. Used with the `records` mutex.
    available_wakeup: Condvar,
}

/// The internal records of a [`ThreadPool`].
struct PoolRecords {
    queue: VecDeque<Box<dyn FnOnce() + Send + 'static>>,
    available_workers: usize,
    next_auxiliary_id: u64,
    shutting_down: bool,
}

impl ThreadGroup {
    /// Starts a new [`ThreadPool`] in this `ThreadGroup`.
    pub fn start_pool(
        self: &Arc<Self>,
        name: Option<String>,
        permanent_workers: usize,
    ) -> Result<Arc<ThreadPool>, Error> {
        let mut records = self.records.lock().unwrap();
        if records.shutting_down {
            return Err(Error::ShuttingDown);
        }

        let entry = records.pools.vacant_entry();
        let name = name.unwrap_or_else(|| "anonymous pool".to_owned());
        let pool = Arc::new(ThreadPool {
            group: self.clone(),
            key: entry.key(),
            name,
            records: Mutex::new(PoolRecords {
                queue: VecDeque::with_capacity(permanent_workers),
                available_workers: 0,
                next_auxiliary_id: 0,
                shutting_down: false,
            }),
            task_wakeup: Condvar::new(),
            available_wakeup: Condvar::new(),
        });
        entry.insert(pool.clone());

        let result = start_pool_workers(self, &mut records, &pool, permanent_workers, &pool.name);
        if result.is_err() {
            // This will shut down any workers that successfully
            // started.
            pool.shut_down_without_removing();
            records.pools.remove(pool.key);
        }
        result.map_err(Into::into).and(Ok(pool))
    }
}

impl ThreadPool {
    /// Submits a task. If no permanent worker thread is available to
    /// run it, this will block until one becomes available.
    pub fn submit<F>(self: &Arc<Self>, task: F) -> Result<(), Error>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut records = self.records.lock().unwrap();
        loop {
            if records.shutting_down {
                return Err(Error::ShuttingDown);
            } else if records.available_workers > records.queue.len() {
                break;
            }
            records = self.available_wakeup.wait(records).unwrap();
        }
        records.queue.push_back(Box::new(task));
        self.task_wakeup.notify_one();
        Ok(())
    }

    /// Submits a task. If no permanent worker thread is available to
    /// run it, then an auxiliary worker thread will be spawned to run
    /// it. The auxiliary worker terminates after the completion of the
    /// task.
    pub fn submit_or_spawn<F>(self: &Arc<Self>, task: F) -> Result<(), Error>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut records = self.records.lock().unwrap();
        if records.shutting_down {
            Err(Error::ShuttingDown)
        } else if records.available_workers > records.queue.len() {
            records.queue.push_back(Box::new(task));
            self.task_wakeup.notify_one();
            Ok(())
        } else {
            // No pooled worker is available, so we create a one-shot
            // auxiliary worker thread to run this task.
            let id = records.next_auxiliary_id;
            records.next_auxiliary_id += 1;
            drop(records);
            let name = format!("{} auxiliary worker {}", self.name, id);
            self.group.start_oneshot(Some(name), task)
        }
    }

    /// Shuts down the `ThreadPool`. (The parent [`ThreadGroup`] is
    /// *not* shut down.)
    pub fn shut_down(&self) {
        let mut group_records = self.group.records.lock().unwrap();
        group_records.pools.remove(self.key);
        drop(group_records);
        self.shut_down_without_removing();
    }

    /// Shuts down the `ThreadPool`, without removing it from its parent
    /// [`ThreadGroup`]'s collection of pools. This exists for
    /// [`ThreadGroup`] code that has already acquired the group's
    /// records mutex for itself and can do the removal manually.
    fn shut_down_without_removing(&self) {
        let mut records = self.records.lock().unwrap();
        records.shutting_down = true;
        self.task_wakeup.notify_all();
        self.available_wakeup.notify_all();
    }

    /// Returns whether the `ThreadPool` is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.records.lock().unwrap().shutting_down
    }
}

/// Tries to start the permanent worker threads of a [`ThreadPool`].
/// Note that on failure, some workers may still be active!
fn start_pool_workers(
    group: &Arc<ThreadGroup>,
    group_records: &mut MutexGuard<GroupRecords>,
    pool: &Arc<ThreadPool>,
    permanent_workers: usize,
    base_name: &str,
) -> io::Result<()> {
    for i in 0..permanent_workers {
        let pool = pool.clone();
        let name = format!("{} worker {}", base_name, i);
        let task = move || pool_worker_loop(pool.clone());
        start_respawnable(group.clone(), group_records, Some(name), Arc::new(task))?;
    }
    Ok(())
}

/// The get task/run task loop for [`ThreadPool`] permanent worker
/// threads.
fn pool_worker_loop(pool: Arc<ThreadPool>) {
    loop {
        let mut records = pool.records.lock().unwrap();
        records.available_workers += 1;
        pool.available_wakeup.notify_one();
        loop {
            if !records.queue.is_empty() {
                break;
            } else if records.shutting_down {
                return;
            }
            records = pool.task_wakeup.wait(records).unwrap();
        }
        let task = records.queue.pop_front().unwrap();
        records.available_workers -= 1;
        drop(records);
        task();
    }
}

////////////////////////////////////////////////////////////////////////
// ERRORS                                                             //
////////////////////////////////////////////////////////////////////////

/// An error type for [`ThreadGroup`] and [`ThreadPool`] operations.
#[derive(Debug)]
pub enum Error {
    /// An OS-level error occurred during the creation of a thread.
    Io(io::Error),

    /// The [`ThreadGroup`] or [`ThreadPool`] is shutting down.
    ShuttingDown,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::ShuttingDown => f.write_str("thread group or pool is shutting down"),
        }
    }
}

impl std::error::Error for Error {}

////////////////////////////////////////////////////////////////////////
// TESTS                                                              //
////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn await_shutdown_works() {
        let exited = Arc::new(Mutex::new(0));
        let group = ThreadGroup::new();
        const SLEEP_DURATION: Duration = Duration::from_millis(100);
        let start = Instant::now();
        for _ in 0..2 {
            let exited_cloned = exited.clone();
            let group_cloned = group.clone();
            group
                .start_oneshot(None, move || loop {
                    thread::sleep(SLEEP_DURATION);
                    if group_cloned.is_shutting_down() {
                        *exited_cloned.lock().unwrap() += 1;
                        return;
                    }
                })
                .unwrap();
        }
        group.shut_down();
        group.await_shutdown();
        assert!(Instant::now().duration_since(start) > SLEEP_DURATION);
        assert_eq!(*exited.lock().unwrap(), 2);
    }

    #[test]
    fn respawnable_threads_respawn() {
        let times_executed = Arc::new(Mutex::new(0));
        let times_executed_cloned = times_executed.clone();
        let wakeup = Arc::new(Condvar::new());
        let wakeup_cloned = wakeup.clone();
        let group = ThreadGroup::new();
        group
            .start_respawnable(None, move || {
                let mut times_executed = times_executed_cloned.lock().unwrap();
                *times_executed += 1;
                wakeup_cloned.notify_all();
            })
            .unwrap();
        let times_executed = times_executed.lock().unwrap();
        let times_executed = wakeup.wait_while(times_executed, |n| *n < 2).unwrap();
        assert!(*times_executed >= 2);
        group.shut_down();
    }

    #[test]
    fn thread_group_rejects_new_threads_after_shutdown() {
        let group = ThreadGroup::new();
        group.shut_down();
        assert!(matches!(
            group.start_oneshot(None, || ()),
            Err(Error::ShuttingDown)
        ));
        assert!(matches!(
            group.start_respawnable(None, || ()),
            Err(Error::ShuttingDown)
        ));
    }

    #[test]
    fn thread_pool_works() {
        let tasks_completed = Arc::new(Mutex::new(0));
        let group = ThreadGroup::new();
        let pool = group.start_pool(None, 2).unwrap();
        for _ in 0..8 {
            let tasks_completed = tasks_completed.clone();
            pool.submit(move || {
                thread::sleep(Duration::from_millis(50));
                *tasks_completed.lock().unwrap() += 1;
            })
            .unwrap();
        }
        group.shut_down();
        group.await_shutdown();
        assert_eq!(*tasks_completed.lock().unwrap(), 8);
    }

    #[test]
    fn thread_pool_rejects_new_tasks_after_shutdown() {
        let group = ThreadGroup::new();
        let pool = group.start_pool(None, 0).unwrap();
        pool.shut_down();
        assert!(matches!(pool.submit(|| ()), Err(Error::ShuttingDown)));
    }

    #[test]
    fn thread_pool_tracking_works() {
        let group = ThreadGroup::new();
        assert_eq!(group.records.lock().unwrap().pools.len(), 0);
        let pool1 = group.start_pool(None, 0).unwrap();
        assert_eq!(group.records.lock().unwrap().pools.len(), 1);
        let pool2 = group.start_pool(None, 0).unwrap();
        assert_eq!(group.records.lock().unwrap().pools.len(), 2);
        pool1.shut_down();
        assert_eq!(group.records.lock().unwrap().pools.len(), 1);
        pool2.shut_down();
        assert_eq!(group.records.lock().unwrap().pools.len(), 0);
    }

    #[test]
    fn thread_group_shut_down_stops_pools() {
        let group = ThreadGroup::new();
        let pool = group.start_pool(None, 0).unwrap();
        group.shut_down();
        assert!(pool.is_shutting_down());
        assert_eq!(group.records.lock().unwrap().pools.len(), 0);
    }
}
