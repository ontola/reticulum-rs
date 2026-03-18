use core::future::Future;
use core::time::Duration;

/// Minimal trait for spawning async tasks.
pub trait Spawner
{
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static;
}

/// Minimal trait for sleeping/delays.
pub trait Timer
{
    type SleepFuture<'a>: Future<Output = ()> + Send + 'a
    where
        Self: 'a;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture<'_>;
}

/// Marker trait for a runtime that can both spawn and sleep.
pub trait Runtime: Spawner + Timer + Clone + Send + Sync + 'static
{
}

impl<T> Runtime for T where T: Spawner + Timer + Clone + Send + Sync + 'static
{
}

