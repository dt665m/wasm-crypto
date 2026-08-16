#set dotenv-load
alias b := build 
alias it := integration-test 

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
    rustup target add wasm32-wasip1

###########################################################
### Build 

# Build Wasm-wasi with +multivalue feature (for multiple return values in wasm)
build:
    #!/usr/bin/env bash
    set -euxo pipefail
    cargo build --target wasm32-wasip1 --release
    cp ./target/wasm32-wasip1/release/wasm_crypto.wasm ./host-wrappers/rust/src/wasm_crypto.wasi.wasm
    cp ./target/wasm32-wasip1/release/wasm_crypto.wasm ./host-wrappers/go/wasm_crypto.wasi.wasm

tag:
	git tag -a v{{SEM_VER}} -m "v{{SEM_VER}}"

untag:
	git tag -d v{{SEM_VER}}

###########################################################
### Testing 

integration-test: build
    #!/usr/bin/env bash
    #set -euxo pipefail
    RUST_BACKTRACE=1 cargo test --release --test integration -- --nocapture
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
