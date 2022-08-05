package WasmSigner 

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	_ "embed"

	"github.com/bytecodealliance/wasmtime-go"
)

//go:embed wasm_crypto.wasi.wasm
var wasm_bytes []byte

type WasmSigner struct {
	mu       sync.Mutex
	store    *wasmtime.Store
	engine   *wasmtime.Engine
	linker   *wasmtime.Linker
	instance *wasmtime.Instance
}

func NewWasmSigner() (*WasmSigner, error) {
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(engine)

	// Configure WASI imports to write stdout into a file.
	wasiConfig := wasmtime.NewWasiConfig()
	// wasiConfig.SetStdoutFile(stdoutPath)
	wasiConfig.InheritEnv()
	store.SetWasi(wasiConfig)
	linker.DefineWasi()


	// Create our module
	module, err := wasmtime.NewModule(store.Engine, wasm_bytes)
	if err != nil {
		return nil, err
	}
	instance, err := linker.Instantiate(store, module)
	if err != nil {
		return nil, err
	}

	return &WasmSigner{
		store:  store,
		engine: engine,
		linker: linker, instance: instance,
	}, nil
}

func (c *WasmSigner) SignRecoverable(secretKey, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	secp256k1Sign := c.instance.GetExport(c.store, "sign_secp256k1_recoverable").Func()

	messageLen := int32(32)
	secretKeyLen := int32(len(secretKey))

	// Allocate
	keyAlloc, err := mAlloc.Call(c.store, secretKeyLen)
	if err != nil {
		return nil, err
	}
	keyPtr, _ := keyAlloc.(int32)
	msgAlloc, err := mAlloc.Call(c.store, messageLen)
	if err != nil {
		return nil, err
	}
	msgPtr, _ := msgAlloc.(int32)

	buf := memory.UnsafeData(c.store)
	copy(buf[keyPtr:keyPtr+secretKeyLen], secretKey)
	copy(buf[msgPtr:msgPtr+messageLen], message)
	callResult, err := secp256k1Sign.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen)
	if err != nil {
		return nil, err
	}
	res := callResult.([]wasmtime.Val)

	outputPtr := res[0].I32()
	outputLen := res[1].I32()
	output := make([]byte, outputLen)
	copy(output, buf[outputPtr:outputPtr+outputLen])

	// Free
    if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, outputPtr, outputLen); err != nil {
		return nil, err
    }

	return output, nil
}

func (c *WasmSigner) SignKeccak256Recoverable(secretKey, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	secp256k1Sign := c.instance.GetExport(c.store, "sign_keccak256_secp256k1_recoverable").Func()

	messageLen := int32(32)
	secretKeyLen := int32(len(secretKey))

	// Allocate
	keyAlloc, err := mAlloc.Call(c.store, secretKeyLen)
	if err != nil {
		return nil, err
	}
	keyPtr, _ := keyAlloc.(int32)
	msgAlloc, err := mAlloc.Call(c.store, messageLen)
	if err != nil {
		return nil, err
	}
	msgPtr, _ := msgAlloc.(int32)

	buf := memory.UnsafeData(c.store)
	copy(buf[keyPtr:keyPtr+secretKeyLen], secretKey)
	copy(buf[msgPtr:msgPtr+messageLen], message)
	callResult, err := secp256k1Sign.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen)
	if err != nil {
		return nil, err
	}
	res := callResult.([]wasmtime.Val)

	outputPtr := res[0].I32()
	outputLen := res[1].I32()
	output := make([]byte, outputLen)
	copy(output, buf[outputPtr:outputPtr+outputLen])

	// Free
    if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, outputPtr, outputLen); err != nil {
		return nil, err
    }

	return output, nil
}

func (c *WasmSigner) SignToDer(secretKey, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	secp256k1Sign := c.instance.GetExport(c.store, "sign_secp256k1_to_der").Func()

	messageLen := int32(32)
	secretKeyLen := int32(len(secretKey))

	// Allocate
	keyAlloc, err := mAlloc.Call(c.store, secretKeyLen)
	if err != nil {
		return nil, err
	}
	keyPtr, _ := keyAlloc.(int32)
	msgAlloc, err := mAlloc.Call(c.store, messageLen)
	if err != nil {
		return nil, err
	}
	msgPtr, _ := msgAlloc.(int32)

	buf := memory.UnsafeData(c.store)
	copy(buf[keyPtr:keyPtr+secretKeyLen], secretKey)
	copy(buf[msgPtr:msgPtr+messageLen], message)
	callResult, err := secp256k1Sign.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen)
	if err != nil {
		return nil, err
	}
	res := callResult.([]wasmtime.Val)

	outputPtr := res[0].I32()
	outputLen := res[1].I32()
	output := make([]byte, outputLen)
	copy(output, buf[outputPtr:outputPtr+outputLen])

	// Free
    if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
        return nil, err
    }
    if _, err = mFree.Call(c.store, outputPtr, outputLen); err != nil {
		return nil, err
    }

	return output, nil
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
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
