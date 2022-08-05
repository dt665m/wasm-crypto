#set dotenv-load
alias b := build 
alias ti := test-integ

# Path and Variables
ORG := "dt665m"
PROJECT := "wasm-crypto"
REPO := "https://github.com" / ORG / PROJECT
ROOT_DIR := justfile_directory()
SEM_VER := `awk -F' = ' '$1=="version"{print $2;exit;}' ./Cargo.toml`

default:
    @just --choose

semver:
    @echo {{SEM_VER}}

###########################################################
### Dependencies 

deps: deps-rust

deps-rust:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

deps-wasm:
    curl https://wasmtime.dev/install.sh -sSf | bash
    cargo install cargo-wasi

###########################################################
### Build 

# Build Wasm-wasi with +multivalue feature (for multiple return values in wasm)
build:
    #!/usr/bin/env bash
    set -euxo pipefail
    RUSTFLAGS="-C target-feature=+multivalue" cargo wasi build --release
    cp ./target/wasm32-wasi/release/wasm_crypto.wasi.wasm ./host-wrappers/rust/src
    cp ./target/wasm32-wasi/release/wasm_crypto.wasi.wasm ./host-wrappers/go

tag:
	git tag -a v{{SEM_VER}} -m "v{{SEM_VER}}"

untag:
	git tag -d v{{SEM_VER}}

###########################################################
### Testing 

test-integ: build
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo test --test integration -- --nocapture
    pushd tests/integration-go
    go test

test NAME="":
    cargo test '{{NAME}}' -- --nocapture

###########################################################
### Docker


###########################################################
### Tooling

clippy-hack:
	# https://github.com/rust-lang/rust-clippy/issues/4612
	$(shell find . | grep "\.rs$"" | xargs touch ; cargo clippy) 

###########################################################
### Integration Tests

