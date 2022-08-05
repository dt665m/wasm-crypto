module wasm-signer-test

go 1.18

require github.com/dt665m/wasm-crypto/host-wrappers/go v0.0.0-20220805093823-8abb12e93dcf
replace github.com/dt665m/wasm-crypto/host-wrappers/go v0.0.0-20220805093823-8abb12e93dcf => "../../host-wrappers/go"

require github.com/bytecodealliance/wasmtime-go v0.39.0 // indirect
