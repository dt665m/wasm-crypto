use anyhow::{bail, Context, Result};
use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};
use wasmtime_wasi::{p1, WasiCtxBuilder};

const WASM_CRYPTO: &[u8] = include_bytes!("./wasm_crypto.wasi.wasm");
const SECP256K1_PREHASH_LENGTH: usize = 32;
const RAW_VEC_LENGTH: usize = 8;

/// Wasmtime host for the crypto guest. A store is intentionally serialized by
/// `&mut self`: Wasmtime stores are not safe for concurrent calls.
pub struct WasmCrypto {
    store: Store<p1::WasiP1Ctx>,
    instance: Instance,
}

#[derive(Clone, Copy)]
struct Allocation {
    ptr: i32,
    len: i32,
}

type Allocator = TypedFunc<i32, i32>;
type Deallocator = TypedFunc<(i32, i32), ()>;
type GuestAllocators = (Memory, Allocator, Deallocator);

impl WasmCrypto {
    pub fn new() -> Result<Self> {
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |ctx| ctx)?;

        // The guest uses no I/O, environment, filesystem, or network access.
        let wasi = WasiCtxBuilder::new().build_p1();
        let mut store = Store::new(&engine, wasi);
        let module = Module::new(&engine, WASM_CRYPTO)?;
        let instance = linker.instantiate(&mut store, &module)?;

        Ok(Self { store, instance })
    }

    pub fn sign_secp256k1(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
        recoverable: bool,
    ) -> Result<Vec<u8>> {
        require_prehash(message)?;
        self.with_inputs(&[secret_key, message], |this, memory, m_free, inputs| {
            let func = this
                .instance
                .get_typed_func::<(i32, i32, i32, i32, i32), i32>(
                    &mut this.store,
                    "sign_secp256k1",
                )?;
            let result_ptr = func.call(
                &mut this.store,
                (
                    inputs[0].ptr,
                    inputs[0].len,
                    inputs[1].ptr,
                    inputs[1].len,
                    wasm_bool(recoverable),
                ),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn sign_keccak256_recoverable(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.with_inputs(&[secret_key, message], |this, memory, m_free, inputs| {
            let func = this.instance.get_typed_func::<(i32, i32, i32, i32), i32>(
                &mut this.store,
                "sign_keccak256_secp256k1_recoverable",
            )?;
            let result_ptr = func.call(
                &mut this.store,
                (inputs[0].ptr, inputs[0].len, inputs[1].ptr, inputs[1].len),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn xpriv_sign_secp256k1(
        &mut self,
        xpriv: &[u8],
        message: &[u8],
        recoverable: bool,
    ) -> Result<Vec<u8>> {
        require_prehash(message)?;
        self.with_inputs(&[xpriv, message], |this, memory, m_free, inputs| {
            let func = this
                .instance
                .get_typed_func::<(i32, i32, i32, i32, i32), i32>(
                    &mut this.store,
                    "xpriv_sign_secp256k1",
                )?;
            let result_ptr = func.call(
                &mut this.store,
                (
                    inputs[0].ptr,
                    inputs[0].len,
                    inputs[1].ptr,
                    inputs[1].len,
                    wasm_bool(recoverable),
                ),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn xpriv_child_sign_secp256k1(
        &mut self,
        xpriv: &[u8],
        message: &[u8],
        recoverable: bool,
        child_index: i32,
    ) -> Result<Vec<u8>> {
        require_prehash(message)?;
        require_child_index(child_index)?;
        self.with_inputs(&[xpriv, message], |this, memory, m_free, inputs| {
            let func = this
                .instance
                .get_typed_func::<(i32, i32, i32, i32, i32, i32), i32>(
                    &mut this.store,
                    "xpriv_child_sign_secp256k1",
                )?;
            let result_ptr = func.call(
                &mut this.store,
                (
                    inputs[0].ptr,
                    inputs[0].len,
                    inputs[1].ptr,
                    inputs[1].len,
                    wasm_bool(recoverable),
                    child_index,
                ),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn public_key(&mut self, secret_key: &[u8], compressed: bool) -> Result<Vec<u8>> {
        self.with_inputs(&[secret_key], |this, memory, m_free, inputs| {
            let func = this.instance.get_typed_func::<(i32, i32, i32), i32>(
                &mut this.store,
                "public_key_from_secret",
            )?;
            let result_ptr = func.call(
                &mut this.store,
                (inputs[0].ptr, inputs[0].len, wasm_bool(compressed)),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn public_key_xpriv(&mut self, xpriv: &[u8], compressed: bool) -> Result<Vec<u8>> {
        self.with_inputs(&[xpriv], |this, memory, m_free, inputs| {
            let func = this
                .instance
                .get_typed_func::<(i32, i32, i32), i32>(&mut this.store, "public_key_from_xpriv")?;
            let result_ptr = func.call(
                &mut this.store,
                (inputs[0].ptr, inputs[0].len, wasm_bool(compressed)),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    pub fn public_key_xpriv_child(
        &mut self,
        xpriv: &[u8],
        compressed: bool,
        child_index: i32,
    ) -> Result<Vec<u8>> {
        require_child_index(child_index)?;
        self.with_inputs(&[xpriv], |this, memory, m_free, inputs| {
            let func = this.instance.get_typed_func::<(i32, i32, i32, i32), i32>(
                &mut this.store,
                "public_key_from_xpriv_child",
            )?;
            let result_ptr = func.call(
                &mut this.store,
                (
                    inputs[0].ptr,
                    inputs[0].len,
                    wasm_bool(compressed),
                    child_index,
                ),
            )?;
            this.extract_result(memory, m_free, result_ptr)
        })
    }

    fn with_inputs<T>(
        &mut self,
        inputs: &[&[u8]],
        call: impl FnOnce(&mut Self, &Memory, &TypedFunc<(i32, i32), ()>, &[Allocation]) -> Result<T>,
    ) -> Result<T> {
        let (memory, m_alloc, m_free) = self.allocators()?;
        let mut allocations = Vec::with_capacity(inputs.len());
        for input in inputs {
            match self.allocate_input(&memory, &m_alloc, input) {
                Ok(allocation) => allocations.push(allocation),
                Err(error) => {
                    let _ = self.release_inputs(&memory, &m_free, &allocations);
                    return Err(error);
                }
            }
        }

        let result = call(self, &memory, &m_free, &allocations);
        let cleanup = self.release_inputs(&memory, &m_free, &allocations);
        match result {
            Ok(value) => {
                cleanup?;
                Ok(value)
            }
            Err(error) => {
                let _ = cleanup;
                Err(error)
            }
        }
    }

    fn allocators(&mut self) -> Result<GuestAllocators> {
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .context("wasm crypto module does not export memory")?;
        let m_alloc = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, "m_alloc")?;
        let m_free = self
            .instance
            .get_typed_func::<(i32, i32), ()>(&mut self.store, "m_free")?;
        Ok((memory, m_alloc, m_free))
    }

    fn allocate_input(
        &mut self,
        memory: &Memory,
        m_alloc: &TypedFunc<i32, i32>,
        input: &[u8],
    ) -> Result<Allocation> {
        let len = wasm_length(input.len())?;
        let ptr = m_alloc.call(&mut self.store, len)?;
        memory
            .write(&mut self.store, wasm_offset(ptr)?, input)
            .context("write guest input")?;
        Ok(Allocation { ptr, len })
    }

    fn release_inputs(
        &mut self,
        memory: &Memory,
        m_free: &TypedFunc<(i32, i32), ()>,
        allocations: &[Allocation],
    ) -> Result<()> {
        for allocation in allocations.iter().rev() {
            let zeroes = vec![0; allocation.len as usize];
            let _ = memory.write(&mut self.store, wasm_offset(allocation.ptr)?, &zeroes);
            m_free.call(&mut self.store, (allocation.ptr, allocation.len))?;
        }
        Ok(())
    }

    fn extract_result(
        &mut self,
        memory: &Memory,
        m_free: &TypedFunc<(i32, i32), ()>,
        result_ptr: i32,
    ) -> Result<Vec<u8>> {
        let result_ptr_offset = wasm_offset(result_ptr)?;
        let mut descriptor = [0; RAW_VEC_LENGTH];
        memory
            .read(&mut self.store, result_ptr_offset, &mut descriptor)
            .context("read guest result descriptor")?;

        let data_ptr = i32::from_le_bytes(descriptor[..4].try_into().expect("fixed pointer size"));
        let data_len = i32::from_le_bytes(descriptor[4..].try_into().expect("fixed length size"));
        let data_ptr_offset = wasm_offset(data_ptr)?;
        let data_len = usize::try_from(data_len).context("negative guest result length")?;

        let mut result = vec![0; data_len];
        let read_result = memory
            .read(&mut self.store, data_ptr_offset, &mut result)
            .context("read guest result bytes");
        let free_data = m_free.call(&mut self.store, (data_ptr, i32::try_from(data_len)?));
        let free_descriptor = m_free.call(&mut self.store, (result_ptr, RAW_VEC_LENGTH as i32));

        read_result?;
        free_data?;
        free_descriptor?;
        Ok(result)
    }
}

fn require_prehash(message: &[u8]) -> Result<()> {
    if message.len() != SECP256K1_PREHASH_LENGTH {
        bail!(
            "secp256k1 message must be a {SECP256K1_PREHASH_LENGTH}-byte prehash, got {} bytes",
            message.len()
        );
    }
    Ok(())
}

fn require_child_index(child_index: i32) -> Result<()> {
    if child_index < 0 {
        bail!("BIP32 child index must not be negative");
    }
    Ok(())
}

fn wasm_length(length: usize) -> Result<i32> {
    i32::try_from(length).context("input is too large for wasm32 memory")
}

fn wasm_offset(offset: i32) -> Result<usize> {
    usize::try_from(offset).context("guest returned a negative memory offset")
}

fn wasm_bool(value: bool) -> i32 {
    i32::from(value)
}
