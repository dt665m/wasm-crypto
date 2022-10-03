# A growing toolbox of Wasm-compiled cryptography with FFI to Wasmtime-Wasi

## Supported Shims
- Rust
- Go

## Watch
Eventually we want to migrate to [witbindgen](https://github.com/bytecodealliance/wit-bindgen) when the ABI descriptor matures and ideally
supports Go and Rust.

## Reading
- https://petermalmgren.com/serverside-wasm-data/
- https://github.com/pmalmgren/wasi-data-sharing/blob/shared-linear-memory-demo/src/main.rs
- https://github.com/stusmall/wasm-udf-example/blob/main/runner/src/main.rs
- https://adlrocha.substack.com/p/adlrocha-playing-with-wasmtime-and
- https://radu-matei.com/blog/practical-guide-to-wasm-memory/
- https://github.com/fermyon/spin/tree/main/sdk/rust
