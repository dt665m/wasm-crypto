package WasmCrypto

import (
	"fmt"
	"sync"

	wasmtime "github.com/bytecodealliance/wasmtime-go/v47"
)

// Runtime owns immutable, compiled Wasmtime state that can be shared by many
// concurrent signers. Each signer still receives an independent Store,
// Instance, and linear memory.
type Runtime struct {
	mu     sync.Mutex
	active sync.WaitGroup
	engine *wasmtime.Engine
	module *wasmtime.Module
	closed bool
	done   chan struct{}
}

// NewRuntime compiles the embedded WASM module once for reuse across signers.
func NewRuntime() (*Runtime, error) {
	engine := wasmtime.NewEngine()
	module, err := wasmtime.NewModule(engine, wasmBytes)
	if err != nil {
		engine.Close()
		return nil, fmt.Errorf("compile wasm crypto module: %w", err)
	}
	return &Runtime{
		engine: engine,
		module: module,
		done:   make(chan struct{}),
	}, nil
}

// NewWasmCrypto creates an isolated signer from the shared compiled module.
// The returned signer must be closed by its caller.
func (r *Runtime) NewWasmCrypto() (*WasmCrypto, error) {
	engine, module, err := r.acquire()
	if err != nil {
		return nil, err
	}

	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(engine)
	closeSigner := func() {
		linker.Close()
		store.Close()
		r.release()
	}

	// The guest only needs the WASI ABI; do not pass the host environment,
	// filesystem, stdin, or stdout through to a signing process.
	store.SetWasi(wasmtime.NewWasiConfig())
	if err := linker.DefineWasi(); err != nil {
		closeSigner()
		return nil, fmt.Errorf("define WASI imports: %w", err)
	}

	instance, err := linker.Instantiate(store, module)
	if err != nil {
		closeSigner()
		return nil, fmt.Errorf("instantiate wasm crypto module: %w", err)
	}

	return &WasmCrypto{
		store:    store,
		linker:   linker,
		instance: instance,
		runtime:  r,
	}, nil
}

func (r *Runtime) acquire() (*wasmtime.Engine, *wasmtime.Module, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, fmt.Errorf("wasm crypto runtime is closed")
	}
	r.active.Add(1)
	return r.engine, r.module, nil
}

func (r *Runtime) release() {
	r.active.Done()
}

// Close prevents new signers, waits for existing signers to close, and then
// releases the shared compiled Module and Engine. It is safe to call more than
// once or concurrently.
func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closed {
		done := r.done
		r.mu.Unlock()
		<-done
		return nil
	}
	r.closed = true
	done := r.done
	r.mu.Unlock()

	r.active.Wait()
	r.module.Close()
	r.engine.Close()

	r.mu.Lock()
	r.module = nil
	r.engine = nil
	close(done)
	r.mu.Unlock()
	return nil
}
