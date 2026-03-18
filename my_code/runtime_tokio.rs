use core::future::Future;
use core::time::Duration;

use crate::my_code::runtime::{Spawner, Timer};

/// Tokio-backed implementation of the generic runtime traits.
#[derive(Clone)]
pub struct TokioRuntime;

impl Spawner for TokioRuntime
{
    fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + 'static,
    {
        tokio::spawn(fut);
    }
}

impl Timer for TokioRuntime
{
    type SleepFuture<'a> = tokio::time::Sleep;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture<'_>
    {
        tokio::time::sleep(duration)
    }
}

