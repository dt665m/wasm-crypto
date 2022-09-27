module wasm-signer-test

go 1.18

require (
	github.com/dt665m/wasm-crypto/host-wrappers/go v0.0.0-20220805093823-8abb12e93dcf
	github.com/stretchr/testify v1.8.0
)

require (
	github.com/bytecodealliance/wasmtime-go v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/dt665m/wasm-crypto/host-wrappers/go => ../../host-wrappers/go
