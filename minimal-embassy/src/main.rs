#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{main, time::Instant};
use esp_println::println;

#[main]
fn main() -> ! {
    let _peripherals = esp_hal::init(esp_hal::Config::default());

    // If you see this, the bootloader finally accepted the app!
    println!("\n\n*******************************");
    println!("*   LILYGO T-Halow BOOTED!    *");
    println!("*******************************\n");

    loop {
        // Your logic here
    }
}
