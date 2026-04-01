# Minimal Embassy Rust

Run rust on your t-halow!

## Run this badboyy

```sh
cargo install espup
espup install
# Set the correct ENVs, use this bash script or source in some other way
. $HOME/export-esp.sh
# espflash version 3+ and 4+ dded strict app descriptor validation that rejects valid no_std binaries
cargo install espflash --version "^2" --force
# ESP needs --release for decent performance
# Select your T-Halow e.g. `/dev/cu.usbmodem11301`
cargo +esp run --release
```
