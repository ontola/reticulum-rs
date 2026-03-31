#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::Timer;
use esp_hal::clock::ClockControl;
use esp_hal::peripherals::Peripherals;
use esp_hal::prelude::*;
use log::info;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();
    let _clocks = ClockControl::max(system.clock_control).freeze();

    info!("HELLO WORLD!");

    loop {
        Timer::delay_secs(1).await;
        info!("Tick!");
    }
}
