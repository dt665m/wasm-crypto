package WasmCrypto

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/bytecodealliance/wasmtime-go"
)

//go:embed wasm_crypto.wasi.wasm
var wasm_bytes []byte

type WasmCrypto struct {
	mu       sync.Mutex
	store    *wasmtime.Store
	engine   *wasmtime.Engine
	linker   *wasmtime.Linker
	instance *wasmtime.Instance
}

func NewWasmCrypto() (*WasmCrypto, error) {
	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(engine)

	// Configure WASI imports to write stdout into a file.
	wasiConfig := wasmtime.NewWasiConfig()
	// wasiConfig.SetStdoutFile(stdoutPath)
	wasiConfig.InheritEnv()
	wasiConfig.InheritStdout()
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

	return &WasmCrypto{
		store:  store,
		engine: engine,
		linker: linker, instance: instance,
	}, nil
}

func (c *WasmCrypto) SignSecp256k1(secretKey, message []byte, recoverable bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	secp256k1Sign := c.instance.GetExport(c.store, "sign_secp256k1").Func()

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
	rec := 0
	if recoverable {
		rec = 1
	}
	callResult, err := secp256k1Sign.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen, rec)
	if err != nil {
		return nil, err
	}
	retPtr := callResult.(int32)

	// Free key
	if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
		return nil, err
	}
	// Free msg
	if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
		return nil, err
	}

	return extract_result(c.store, buf, mFree, retPtr)
}

func (c *WasmCrypto) XPrivSignSecp256k1(xpriv, message []byte, recoverable bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	fn := c.instance.GetExport(c.store, "xpriv_sign_secp256k1").Func()

	messageLen := int32(32)
	secretKeyLen := int32(len(xpriv))

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
	copy(buf[keyPtr:keyPtr+secretKeyLen], xpriv)
	copy(buf[msgPtr:msgPtr+messageLen], message)
	rec := 0
	if recoverable {
		rec = 1
	}
    callResult, err := fn.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen, rec)
	if err != nil {
		return nil, err
	}
	retPtr := callResult.(int32)
	res, err := extract_result(c.store, buf, mFree, retPtr)
	if err != nil {
		return nil, err
	}

	// Free key
	if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
		return nil, err
	}
	// Free msg
	if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *WasmCrypto) XPrivChildSignSecp256k1(xpriv, message []byte, recoverable bool, childIndex int32) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	fn := c.instance.GetExport(c.store, "xpriv_child_sign_secp256k1").Func()

	messageLen := int32(32)
	secretKeyLen := int32(len(xpriv))

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
	copy(buf[keyPtr:keyPtr+secretKeyLen], xpriv)
	copy(buf[msgPtr:msgPtr+messageLen], message)
	rec := 0
	if recoverable {
		rec = 1
	}
	callResult, err := fn.Call(c.store, keyPtr, secretKeyLen, msgPtr, messageLen, rec, childIndex)
	if err != nil {
		return nil, err
	}
	retPtr := callResult.(int32)
	res, err := extract_result(c.store, buf, mFree, retPtr)
	if err != nil {
		return nil, err
	}

	// Free key
	if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
		return nil, err
	}
	// Free msg
	if _, err = mFree.Call(c.store, msgPtr, messageLen); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *WasmCrypto) PublicKey(secretKey []byte, compressed bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	memory := c.instance.GetExport(c.store, "memory").Memory()
	mAlloc := c.instance.GetExport(c.store, "m_alloc").Func()
	mFree := c.instance.GetExport(c.store, "m_free").Func()
	publicKey := c.instance.GetExport(c.store, "public_key_from_secret").Func()

	secretKeyLen := int32(len(secretKey))

	// Allocate
	keyAlloc, err := mAlloc.Call(c.store, secretKeyLen)
	if err != nil {
		return nil, err
	}
	keyPtr, _ := keyAlloc.(int32)

	buf := memory.UnsafeData(c.store)
	copy(buf[keyPtr:keyPtr+secretKeyLen], secretKey)
	comp := 0
	if compressed {
		comp = 1
	}
	callResult, err := publicKey.Call(c.store, keyPtr, secretKeyLen, comp)
	if err != nil {
		return nil, err
	}

	retPtr := callResult.(int32)
	res, err := extract_result(c.store, buf, mFree, retPtr)
	if err != nil {
		return nil, err
	}

	// Free
	if _, err = mFree.Call(c.store, keyPtr, secretKeyLen); err != nil {
		return nil, err
	}

	return res, nil
}

// #HACK we know the C Repr of the Rust `RawVec` return value so we will hack this instead
// of messing with C.GO
// RAW [144, 66, 16, 0, 65, 0, 0, 0]
// RAW STRUCT RawVec { ptr: 1065616, len: 65 }
func extract_result(store *wasmtime.Store, memBuf []byte, mFree *wasmtime.Func, retPtr int32) ([]byte, error) {
	rawLen := 8 // two i32 values
	raw := make([]byte, rawLen)
	copy(raw, memBuf[retPtr:retPtr+int32(rawLen)])

	var dataPtr int32
	rdr := bytes.NewReader(raw)
	err := binary.Read(rdr, binary.LittleEndian, &dataPtr)
	if err != nil {
		fmt.Println("dataPtr binary.Read failed:", err)
		return nil, err
	}
	var dataLen int32
	err = binary.Read(rdr, binary.LittleEndian, &dataLen)
	if err != nil {
		fmt.Println("dataPtr binary.Read failed:", err)
		return nil, err
	}
	// fmt.Printf("DataPtr %d, DataLen %d\n", dataPtr, dataLen)

	ret := make([]byte, dataLen)
	copy(ret, memBuf[dataPtr:dataPtr+dataLen])

	// free the RawVec container
	if _, err = mFree.Call(store, retPtr, rawLen); err != nil {
		return nil, err
	}
	// free the Bytes referenced by RawVec
	if _, err = mFree.Call(store, retPtr, rawLen); err != nil {
		return nil, err
	}

	return ret, nil
}
