package WasmCrypto

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"sync"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v47"
)

const (
	secp256k1PrehashLength = 32
	rawVecLength           = 8
	maxWasmI32             = int(^uint32(0) >> 1)
)

//go:embed wasm_crypto.wasi.wasm
var wasmBytes []byte

type WasmCrypto struct {
	mu          sync.Mutex
	store       *wasmtime.Store
	linker      *wasmtime.Linker
	instance    *wasmtime.Instance
	runtime     *Runtime
	ownsRuntime bool
	closed      bool
}

type wasmAllocation struct {
	ptr int32
	len int32
}

func NewWasmCrypto() (*WasmCrypto, error) {
	runtime, err := NewRuntime()
	if err != nil {
		return nil, err
	}
	signer, err := runtime.NewWasmCrypto()
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	signer.ownsRuntime = true
	return signer, nil
}

// Close immediately releases the signer's native Linker and Store. It also
// releases an internally owned Runtime when the package-level constructor was
// used. It is safe to call more than once. The signer must not be used after
// Close returns.
func (c *WasmCrypto) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	c.instance = nil

	runtime := c.runtime
	ownsRuntime := c.ownsRuntime
	c.runtime = nil
	c.ownsRuntime = false

	if c.linker != nil {
		c.linker.Close()
		c.linker = nil
	}
	if c.store != nil {
		c.store.Close()
		c.store = nil
	}
	if runtime != nil {
		runtime.release()
		if ownsRuntime {
			return runtime.Close()
		}
	}
	return nil
}

// SignSecp256k1 signs a 32-byte prehash. Recoverable signatures are encoded
// as 64-byte r||s followed by a one-byte recovery ID; non-recoverable
// signatures are ASN.1 DER.
func (c *WasmCrypto) SignSecp256k1(secretKey, message []byte, recoverable bool) ([]byte, error) {
	if err := requirePrehash(message); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("sign_secp256k1", [][]byte{secretKey, message}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{
			inputs[0].ptr, inputs[0].len,
			inputs[1].ptr, inputs[1].len,
			wasmBool(recoverable),
		}
	})
}

// SignKeccak256Recoverable hashes message with Keccak-256 before producing an
// r||s||recovery-ID signature.
func (c *WasmCrypto) SignKeccak256Recoverable(secretKey, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("sign_keccak256_secp256k1_recoverable", [][]byte{secretKey, message}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{
			inputs[0].ptr, inputs[0].len,
			inputs[1].ptr, inputs[1].len,
		}
	})
}

func (c *WasmCrypto) XPrivSignSecp256k1(xpriv, message []byte, recoverable bool) ([]byte, error) {
	if err := requirePrehash(message); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("xpriv_sign_secp256k1", [][]byte{xpriv, message}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{
			inputs[0].ptr, inputs[0].len,
			inputs[1].ptr, inputs[1].len,
			wasmBool(recoverable),
		}
	})
}

func (c *WasmCrypto) XPrivChildSignSecp256k1(xpriv, message []byte, recoverable bool, childIndex int32) ([]byte, error) {
	if err := requirePrehash(message); err != nil {
		return nil, err
	}
	if err := requireChildIndex(childIndex); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("xpriv_child_sign_secp256k1", [][]byte{xpriv, message}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{
			inputs[0].ptr, inputs[0].len,
			inputs[1].ptr, inputs[1].len,
			wasmBool(recoverable), childIndex,
		}
	})
}

func (c *WasmCrypto) PublicKey(secretKey []byte, compressed bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("public_key_from_secret", [][]byte{secretKey}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{inputs[0].ptr, inputs[0].len, wasmBool(compressed)}
	})
}

func (c *WasmCrypto) PublicKeyXPriv(xpriv []byte, compressed bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("public_key_from_xpriv", [][]byte{xpriv}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{inputs[0].ptr, inputs[0].len, wasmBool(compressed)}
	})
}

func (c *WasmCrypto) PublicKeyXPrivChild(xpriv []byte, compressed bool, childIndex int32) ([]byte, error) {
	if err := requireChildIndex(childIndex); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.invoke("public_key_from_xpriv_child", [][]byte{xpriv}, func(inputs []wasmAllocation) []interface{} {
		return []interface{}{inputs[0].ptr, inputs[0].len, wasmBool(compressed), childIndex}
	})
}

func (c *WasmCrypto) invoke(
	functionName string,
	inputs [][]byte,
	arguments func([]wasmAllocation) []interface{},
) (result []byte, err error) {
	memory, mAlloc, mFree, function, err := c.exports(functionName)
	if err != nil {
		return nil, err
	}

	allocations := make([]wasmAllocation, 0, len(inputs))
	defer func() {
		cleanupErr := c.releaseInputs(memory, mFree, allocations)
		if err == nil && cleanupErr != nil {
			err = cleanupErr
		}
	}()

	for _, input := range inputs {
		allocation, allocationErr := c.allocateInput(memory, mAlloc, input)
		if allocationErr != nil {
			return nil, allocationErr
		}
		allocations = append(allocations, allocation)
	}

	value, err := function.Call(c.store, arguments(allocations)...)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", functionName, err)
	}
	resultPtr, ok := value.(int32)
	if !ok {
		return nil, fmt.Errorf("%s returned %T, expected i32", functionName, value)
	}

	return c.extractResult(memory, mFree, resultPtr)
}

func (c *WasmCrypto) exports(functionName string) (*wasmtime.Memory, *wasmtime.Func, *wasmtime.Func, *wasmtime.Func, error) {
	if c.closed || c.instance == nil || c.store == nil {
		return nil, nil, nil, nil, fmt.Errorf("wasm crypto signer is closed")
	}
	memoryExport := c.instance.GetExport(c.store, "memory")
	if memoryExport == nil || memoryExport.Memory() == nil {
		return nil, nil, nil, nil, fmt.Errorf("wasm crypto module does not export memory")
	}
	mAllocExport := c.instance.GetExport(c.store, "m_alloc")
	if mAllocExport == nil || mAllocExport.Func() == nil {
		return nil, nil, nil, nil, fmt.Errorf("wasm crypto module does not export m_alloc")
	}
	mFreeExport := c.instance.GetExport(c.store, "m_free")
	if mFreeExport == nil || mFreeExport.Func() == nil {
		return nil, nil, nil, nil, fmt.Errorf("wasm crypto module does not export m_free")
	}
	functionExport := c.instance.GetExport(c.store, functionName)
	if functionExport == nil || functionExport.Func() == nil {
		return nil, nil, nil, nil, fmt.Errorf("wasm crypto module does not export %s", functionName)
	}
	return memoryExport.Memory(), mAllocExport.Func(), mFreeExport.Func(), functionExport.Func(), nil
}

func (c *WasmCrypto) allocateInput(memory *wasmtime.Memory, mAlloc *wasmtime.Func, input []byte) (wasmAllocation, error) {
	length, err := wasmLength(len(input))
	if err != nil {
		return wasmAllocation{}, err
	}
	value, err := mAlloc.Call(c.store, length)
	if err != nil {
		return wasmAllocation{}, fmt.Errorf("allocate guest input: %w", err)
	}
	ptr, ok := value.(int32)
	if !ok {
		return wasmAllocation{}, fmt.Errorf("m_alloc returned %T, expected i32", value)
	}

	allocation := wasmAllocation{ptr: ptr, len: length}
	guestMemory, err := c.memoryRange(memory, ptr, length)
	if err != nil {
		return wasmAllocation{}, err
	}
	copy(guestMemory, input)
	return allocation, nil
}

func (c *WasmCrypto) releaseInputs(memory *wasmtime.Memory, mFree *wasmtime.Func, allocations []wasmAllocation) error {
	for i := len(allocations) - 1; i >= 0; i-- {
		allocation := allocations[i]
		if guestMemory, err := c.memoryRange(memory, allocation.ptr, allocation.len); err == nil {
			clear(guestMemory)
		}
		if _, err := mFree.Call(c.store, allocation.ptr, allocation.len); err != nil {
			return fmt.Errorf("free guest input: %w", err)
		}
	}
	return nil
}

func (c *WasmCrypto) extractResult(memory *wasmtime.Memory, mFree *wasmtime.Func, resultPtr int32) (result []byte, err error) {
	defer func() {
		if _, freeErr := mFree.Call(c.store, resultPtr, int32(rawVecLength)); err == nil && freeErr != nil {
			err = fmt.Errorf("free guest result descriptor: %w", freeErr)
		}
	}()

	descriptor, err := c.memoryRange(memory, resultPtr, rawVecLength)
	if err != nil {
		return nil, err
	}
	dataPtr := int32(binary.LittleEndian.Uint32(descriptor[:4]))
	dataLen := int32(binary.LittleEndian.Uint32(descriptor[4:]))
	if dataPtr < 0 || dataLen < 0 {
		return nil, fmt.Errorf("guest returned an invalid result descriptor")
	}
	defer func() {
		if _, freeErr := mFree.Call(c.store, dataPtr, dataLen); err == nil && freeErr != nil {
			err = fmt.Errorf("free guest result bytes: %w", freeErr)
		}
	}()

	data, err := c.memoryRange(memory, dataPtr, dataLen)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), data...), nil
}

func (c *WasmCrypto) memoryRange(memory *wasmtime.Memory, ptr, length int32) ([]byte, error) {
	if ptr < 0 || length < 0 {
		return nil, fmt.Errorf("negative wasm memory range")
	}
	end := int64(ptr) + int64(length)
	guestMemory := memory.UnsafeData(c.store)
	if end > int64(len(guestMemory)) {
		return nil, fmt.Errorf("wasm memory range [%d:%d] exceeds %d bytes", ptr, end, len(guestMemory))
	}
	return guestMemory[int(ptr):int(end)], nil
}

func requirePrehash(message []byte) error {
	if len(message) != secp256k1PrehashLength {
		return fmt.Errorf("secp256k1 message must be a %d-byte prehash, got %d bytes", secp256k1PrehashLength, len(message))
	}
	return nil
}

func requireChildIndex(childIndex int32) error {
	if childIndex < 0 {
		return fmt.Errorf("BIP32 child index must not be negative")
	}
	return nil
}

func wasmLength(length int) (int32, error) {
	if length > maxWasmI32 {
		return 0, fmt.Errorf("input is too large for wasm32 memory")
	}
	return int32(length), nil
}

func wasmBool(value bool) int32 {
	if value {
		return 1
	}
	return 0
}
