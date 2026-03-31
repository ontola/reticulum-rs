# Minimal Embassy Rust

Run rust on your t-halow!

## Run this badboyy

```sh
cargo install espup
espup install
# Follow the instructions to source the export script:
. $HOME/export-esp.sh
# espflash version 3+ and 4+ dded strict app descriptor validation that rejects valid no_std binaries
cargo install espflash --version "^2" --force
# ESP needs release otherwise perf will be horrid
cargo run --release
```
