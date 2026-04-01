#![no_std]
#![no_main]

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::main;
use esp_println::println;
use log::info;
use reticulum::hash::AddressHash;

#[main]
fn main() -> ! {
    esp_alloc::heap_allocator!(size: 32 * 1024);
    let _peripherals = esp_hal::init(esp_hal::Config::default());
    let _reticulum_compile_probe = AddressHash::new([0u8; 16]);

    println!("reticulum embassy bootstrap on esp32s3");
    info!("embassy bootstrap started");

    loop {
        core::hint::spin_loop();
    }
}
