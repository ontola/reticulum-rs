# Reticulum-rs on T-Halow

## Running the node

```sh
# ESP needs --release for decent performance
# Select your T-Halow e.g. `/dev/cu.usbmodem11301`
cargo run --release
```

## Requirements

### 1. Rust toolchain (Xtensa)

ESP32-S3 uses Xtensa, which is not supported by upstream Rust. Install the Espressif fork:

```bash
cargo install espup
espup install
# Add to your shell profile, then also run now:
source ~/export-esp.sh
```

### 2. Flashing tool — espflash **3.x only**

**Do not install espflash 4.x.** Version 4.x requires an ESP-IDF App Descriptor in the binary. Bare-metal `esp-hal` apps do not have this descriptor and will fail with:

```
Error: ESP-IDF App Descriptor missing in your `esp-idf` application.
```

Install the last compatible 3.x release explicitly:

```bash
cargo install espflash@3.2.0
```

If you already have 4.x installed, re-run the above — it will replace it.
