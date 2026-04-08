//! Runtime adapter layer for async primitives.
//!
//! Stage C introduces this module so we can swap `tokio` (std) with an
//! Embassy-based async backend (embedded) without rewriting protocol logic.
//!
//! This module is intentionally small: it is the seam where we swap async
//! primitives between a `std` backend (Tokio) and an embedded backend (Embassy).

// --- std backend (Tokio) ----------------------------------------------------

#[cfg(feature = "std")]
mod std_backend {
    use core::future::Future;

    pub use tokio::sync::broadcast;
    pub use tokio::sync::mpsc;
    pub use tokio::sync::Mutex;
    pub use tokio::sync::MutexGuard;

    pub use tokio_util::sync::CancellationToken;

    /// Timer helpers backed by `tokio::time` (std backend).
    pub mod time {
        pub use std::time::Duration;
        pub use tokio::time::{sleep, Instant};
    }

    /// Spawn a background task (std backend).
    pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(fut)
    }

    /// Crate-local select macro.
    ///
    /// Later stages can remap this to an Embassy-friendly implementation.
    #[macro_export]
    macro_rules! async_select {
        ($($t:tt)*) => {
            tokio::select!($($t)*)
        };
    }
}

#[cfg(feature = "std")]
pub use std_backend::*;

// --- embedded backend (Embassy) --------------------------------------------

#[cfg(all(not(feature = "std"), feature = "embedded"))]
mod embedded_backend {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::signal::Signal;

    pub use embassy_sync::mutex::Mutex;
    pub use embassy_sync::mutex::MutexGuard;

    /// Timer helpers backed by `embassy_time` (embedded backend).
    pub mod time {
        pub use core::time::Duration;
        pub use embassy_time::Instant;

        /// Sleep for `duration` (matches the `std::time::Duration` / `core::time::Duration` used by transport).
        pub async fn sleep(duration: core::time::Duration) {
            let micros_u128 = duration.as_micros();
            let micros_u64 = micros_u128.min(u128::from(u64::MAX)) as u64;
            embassy_time::Timer::after(embassy_time::Duration::from_micros(micros_u64)).await;
        }
    }

    /// A minimal cancellation token for embedded.
    ///
    /// This intentionally mirrors the subset of `tokio_util::sync::CancellationToken`
    /// used by `transport.rs`.
    #[derive(Clone)]
    pub struct CancellationToken {
        inner: Arc<CancellationInner>,
    }

    impl core::fmt::Debug for CancellationToken {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("CancellationToken")
                .field("is_cancelled", &self.is_cancelled())
                .finish()
        }
    }

    struct CancellationInner {
        cancelled: AtomicBool,
        signal: Signal<CriticalSectionRawMutex, ()>,
    }

    impl CancellationToken {
        pub fn new() -> Self {
            Self {
                inner: Arc::new(CancellationInner {
                    cancelled: AtomicBool::new(false),
                    signal: Signal::new(),
                }),
            }
        }

        pub fn cancel(&self) {
            if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
                self.inner.signal.signal(());
            }
        }

        pub fn is_cancelled(&self) -> bool {
            self.inner.cancelled.load(Ordering::SeqCst)
        }

        pub async fn cancelled(&self) {
            if self.is_cancelled() {
                return;
            }
            self.inner.signal.wait().await;
        }
    }

    use embassy_executor::raw::TaskPool;
    use embassy_executor::Spawner;

    // `Spawner` is not `Send`, so it cannot live in `Mutex`/`RefCell` behind a `Sync` static.
    // On single-core ESP32-S3 + Embassy this is only touched from the executor thread.
    static mut SPAWNER: Option<Spawner> = None;

    /// Register the Embassy [`Spawner`] once before anything calls [`spawn`].
    ///
    /// Call this from `#[embassy_executor::main] async fn main(spawner: Spawner, ...) { ... }`
    /// (or equivalent) before constructing types that spawn background work (e.g. transport).
    ///
    /// # Safety
    ///
    /// Must be called only during board initialization (single executor thread), before any
    /// concurrent use of [`spawn`].
    #[allow(static_mut_refs)] // Single-threaded executor init; avoids Mutex<Spawner> (!Send).
    pub fn set_spawner(spawner: Spawner) {
        unsafe {
            SPAWNER = Some(spawner);
        }
    }

    /// Spawn a task on the Embassy executor (embedded backend).
    ///
    /// Embassy 0.7 does not accept a raw future; it requires a `SpawnToken` from task storage.
    /// We allocate a one-slot `TaskPool` (leaked) per call so each distinct
    /// `async` block type can be spawned the same way Tokio's `spawn` works.
    ///
    /// # Panics
    ///
    /// Panics if [`set_spawner`] was not called, or if the executor rejects the task.
    #[allow(static_mut_refs)] // Single-threaded executor; `Spawner` is not `Send`.
    pub fn spawn<F>(fut: F)
    where
        F: core::future::Future<Output = ()> + 'static,
    {
        let pool: &'static TaskPool<F, 1> = Box::leak(Box::new(TaskPool::new()));
        let token = pool.spawn(move || fut);
        unsafe {
            SPAWNER
                .as_ref()
                .expect("reticulum: async_backend::set_spawner must be called before spawn on embedded")
                .spawn(token)
                .expect("reticulum: embassy_executor::Spawner::spawn failed");
        }
    }

    /// Same role as `tokio::select!` for the patterns used in `transport.rs`.
    ///
    /// Implemented with `futures::select_biased!` (works on `no_std` + `alloc`).
    #[macro_export]
    macro_rules! async_select {
        ($($t:tt)*) => {
            ::futures::select_biased! { $($t)* }
        };
    }

    /// `tokio::sync::broadcast`-shaped API, backed by an Embassy competing channel.
    ///
    /// Important behavioral difference vs Tokio:
    /// - Tokio broadcast delivers each sent message to *each* receiver.
    /// - Embassy channels have *competing receivers* (a message is received by only one).
    ///
    /// We keep the public API surface (`channel`, `Sender`, `Receiver`, `subscribe`, `send`,
    /// `recv`, `try_recv`) so the transport can be ported incrementally.
    pub mod broadcast {
        extern crate alloc;

        use alloc::boxed::Box;

        use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
        use embassy_sync::channel;

        const DEFAULT_CAPACITY: usize = 16;

        #[derive(Clone)]
        pub struct Sender<T: 'static> {
            tx: channel::DynamicSender<'static, T>,
            rx_for_subscribe: channel::DynamicReceiver<'static, T>,
        }

        #[derive(Clone)]
        pub struct Receiver<T: 'static> {
            rx: channel::DynamicReceiver<'static, T>,
        }

        #[derive(Debug)]
        pub struct SendError<T>(pub T);

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TryRecvError {
            Empty,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RecvError {
            /// Present for API compatibility. Embassy channels don't "close" in our setup.
            Closed,
        }

        pub fn channel<T: 'static>(capacity: usize) -> (Sender<T>, Receiver<T>) {
            // For now, we only need one capacity value in the codebase.
            // If/when we need other sizes, we can expand this match.
            let _ = capacity;

            let ch = Box::leak(Box::new(channel::Channel::<
                CriticalSectionRawMutex,
                T,
                DEFAULT_CAPACITY,
            >::new()));

            let tx = ch.sender().into();
            let rx = ch.receiver().into();

            (
                Sender {
                    tx,
                    rx_for_subscribe: rx,
                },
                Receiver { rx },
            )
        }

        impl<T: 'static> Sender<T> {
            pub fn subscribe(&self) -> Receiver<T> {
                Receiver {
                    rx: self.rx_for_subscribe.clone(),
                }
            }

            pub fn send(&self, message: T) -> Result<usize, SendError<T>> {
                // We purposely use `try_send` to match Tokio's non-async `send`.
                // Returning `1` keeps the "number of receivers" type shape, but is not meaningful
                // for competing receivers.
                match self.tx.try_send(message) {
                    Ok(()) => Ok(1),
                    Err(channel::TrySendError::Full(m)) => Err(SendError(m)),
                }
            }
        }

        impl<T: 'static> Receiver<T> {
            pub async fn recv(&mut self) -> Result<T, RecvError> {
                Ok(self.rx.receive().await)
            }

            pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
                match self.rx.try_receive() {
                    Ok(v) => Ok(v),
                    Err(channel::TryReceiveError::Empty) => Err(TryRecvError::Empty),
                }
            }
        }
    }
}

#[cfg(all(not(feature = "std"), feature = "embedded"))]
pub use embedded_backend::*;

