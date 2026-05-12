use core::future::Future;
use core::time::Duration;

/// Minimal trait for spawning async tasks.
pub trait Spawner {
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static;
}

/// Minimal trait for sleeping/delays.
pub trait Timer {
    type SleepFuture<'a>: Future<Output = ()> + Send + 'a
    where
        Self: 'a;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture<'_>;
}

/// Runtime adapter that can both spawn tasks and sleep.
pub trait Runtime: Spawner + Timer + Clone + Send + Sync + 'static {}

impl<T> Runtime for T where T: Spawner + Timer + Clone + Send + Sync + 'static {}

/// Tokio-backed implementation of the runtime traits.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct TokioRuntime;

#[cfg(feature = "std")]
impl Spawner for TokioRuntime {
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        crate::async_backend::spawn(fut);
    }
}

#[cfg(feature = "std")]
impl Timer for TokioRuntime {
    type SleepFuture<'a> = tokio::time::Sleep;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture<'_> {
        crate::async_backend::time::sleep(duration)
    }
}
