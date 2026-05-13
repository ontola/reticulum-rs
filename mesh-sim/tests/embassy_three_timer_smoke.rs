//! Sanity: three `Executor::run` threads can each `Timer::after` and signal main.
use std::sync::mpsc;
use std::thread;

use embassy_time::{Duration, Timer};

#[embassy_executor::task(pool_size = 24)]
async fn ping(tx: mpsc::Sender<u8>, id: u8) {
    Timer::after(Duration::from_millis(200)).await;
    let _ = tx.send(id);
}

#[test]
fn three_embassy_executor_threads_can_timer_and_signal() {
    let (tx, rx) = mpsc::channel::<u8>();
    for id in 0u8..3 {
        let t = tx.clone();
        thread::spawn(move || {
            let executor = Box::leak(Box::new(embassy_executor::Executor::new()));
            executor.run(|spawner| {
                reticulum::async_backend::embassy::set_spawner(spawner);
                spawner.spawn(ping(t, id)).unwrap();
            });
        });
    }
    drop(tx);
    let mut got = std::collections::HashSet::new();
    for _ in 0..3 {
        let id = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        got.insert(id);
    }
    assert_eq!(got.len(), 3);
}
