# Minimal Embassy Rust

Run rust on your t-halow!

## Run this badboyy

```sh
cargo install espup
espup install
# Follow the instructions to source the export script:
. $HOME/export-esp.sh
cargo install espflash
# ESP needs release otherwise perf will be horrid
cargo run --release
```
