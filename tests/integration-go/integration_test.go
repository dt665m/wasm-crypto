package WasmCryptoTest

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/dt665m/wasm-crypto/host-wrappers/go"
	"github.com/stretchr/testify/assert"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func TestWasmCrypto(t *testing.T) {
	message := make([]byte, 32)
	secretKey, err := hex.DecodeString("71ccdc13ab4775fc012763de2dfafa68bee9169cc27f06ab9107630d7c8f2992")
    xprivB58 := []byte("xprv9s21ZrQH143K3fsbwbm3Q3JcUcd1VSJ2ukikDvzLaLpLbiy7buQqDAiw3LwoNp5RSjreg3G6aVTYa9MjVqAyocx3AjSNH4tgfoXiJftznyN")
    childIndex := int32(1)
	check(err)
	fmt.Println("signing key bytes:", secretKey)

	start := time.Now()
	signer, err1 := WasmCrypto.NewWasmCrypto()
	wasmSig, err2 := signer.SignSecp256k1(secretKey, message, true)
	wasmXprivSig, err3 := signer.XPrivSignSecp256k1(xprivB58, message, true)
	wasmXprivChildSig, err4 := signer.XPrivChildSignSecp256k1(xprivB58, message, true, childIndex)
	wasmPubKey, err5 := signer.PublicKey(secretKey, false)
	wasmPubKeyCompressed, err6 := signer.PublicKey(secretKey, true)

	elapsed := time.Since(start)
	check(err1)
	check(err2)
	check(err3)
	check(err4)
	check(err5)
	check(err6)

	expectedSignature := []byte{
		23, 78, 83, 64, 227, 58, 29, 16, 75, 163, 90, 150, 14, 187, 145, 122, 5, 198, 224, 180, 0, 200, 8, 194, 189, 220, 208, 49, 238, 130, 6, 74, 95, 122, 37, 134, 167, 88, 142, 148, 250, 183, 76, 228, 61, 204, 151, 202, 116, 166, 148, 195, 19, 216, 34, 251, 201, 156, 204, 79, 246, 176, 57, 170, 0,
	}
    expectedXprivSignature := []byte{
        187, 222, 42, 239, 77, 32, 131, 64, 203, 17, 94, 81, 231, 235, 172, 231, 251, 144, 194, 219, 82, 139, 82, 236, 225, 203, 235, 139, 222, 1, 175, 91, 101, 196, 185, 159, 226, 214, 209, 62, 29, 178, 28, 167, 177, 1, 132, 28, 5, 50, 114, 50, 11, 143, 211, 110, 162, 176, 243, 118, 58, 201, 148, 28, 0,
    }
    expectedXprivChildSignature := []byte{
        128, 40, 29, 171, 24, 112, 253, 42, 214, 16, 209, 22, 53, 100, 120, 51, 249, 201, 18, 50, 220, 252, 9, 230, 186, 214, 92, 204, 238, 99, 110, 124, 57, 237, 150, 92, 133, 247, 66, 235, 191, 23, 189, 204, 82, 228, 205, 183, 17, 74, 58, 221, 126, 76, 93, 225, 227, 13, 77, 118, 53, 72, 227, 255, 0,
    }
	expectedPubKey := []byte{
		4, 0, 137, 100, 176, 3, 91, 16, 118, 135, 39, 118, 139, 184, 16, 89, 175, 107, 70, 173, 7, 78, 246, 85, 71, 217, 252, 118, 217, 217, 105, 82, 221, 124, 116, 255, 202, 43, 158, 98, 85, 228, 70, 13, 21, 126, 125, 199, 55, 115, 24, 40, 47, 116, 26, 15, 45, 169, 34, 47, 201, 198, 228, 84, 98,
	}
	expectedPubKeyCompressed := []byte{
		2, 0, 137, 100, 176, 3, 91, 16, 118, 135, 39, 118, 139, 184, 16, 89, 175, 107, 70, 173, 7, 78, 246, 85, 71, 217, 252, 118, 217, 217, 105, 82, 221,
	}
	assert.Equal(t, expectedSignature, wasmSig)
	assert.Equal(t, expectedXprivSignature, wasmXprivSig)
	assert.Equal(t, expectedXprivChildSignature, wasmXprivChildSig)
	assert.Equal(t, expectedPubKey, wasmPubKey)
	assert.Equal(t, expectedPubKeyCompressed, wasmPubKeyCompressed)

	//output for eyeball matching with rust
	fmt.Println("wasm signature:", wasmSig)
	fmt.Println("wasm xpriv signature:", wasmSig)
	fmt.Println("wasm xpriv child signature:", wasmSig)
	fmt.Println("public key:", wasmPubKey)
	fmt.Println("public key length:", len(wasmPubKey))
	fmt.Println("public key compressed:", wasmPubKeyCompressed)
	fmt.Println("public key compressed length:", len(wasmPubKeyCompressed))
	fmt.Printf("elapsed: %s\n", elapsed)
}
