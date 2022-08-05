package WasmSignerTest

import (
	"testing"
    "fmt"
    "time"
    "encoding/hex"

    "github.com/dt665m/wasm-crypto/host-wrappers/go"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func TestWasmSigner(t *testing.T) {
	start := time.Now()

	signer, err := NewWasmSigner()
	check(err)
	message := make([]byte, 32)
	secretKey, err := hex.DecodeString("71ccdc13ab4775fc012763de2dfafa68bee9169cc27f06ab9107630d7c8f2992")
	check(err)
	output, err := signer.signRecoverable(secretKey, message)
	_, err = signer.signKeccak256Recoverable(secretKey, message)
	_, err = signer.signToDer(secretKey, message)
	check(err)

	elapsed := time.Since(start)
	fmt.Println("wasm signature: ", output)
	fmt.Printf("elapsed: %s\n", elapsed)
}
