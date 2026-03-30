#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{main, time::Instant};
use esp_println::println;

// This exact structure is what the ESP-IDF v5.x bootloader looks for.
// We use a 256-byte array to ensure the bootloader doesn't read past it into garbage data.
#[no_mangle]
#[link_section = ".rodata_desc"]
#[used]
static ESP_APP_DESC: [u8; 256] = {
    let mut bytes = [0u8; 256];

    // Magic word: 0xABCD7890 (Little Endian)
    bytes[0] = 0x90;
    bytes[1] = 0x78;
    bytes[2] = 0xCD;
    bytes[3] = 0xAB;

    // Offset 184: min_efuse_blk_rev (Set to 0)
    bytes[184] = 0;
    bytes[185] = 0;

    // Offset 186: max_efuse_blk_rev (Set to 0)
    bytes[186] = 0;
    bytes[187] = 0;

    bytes
};

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
