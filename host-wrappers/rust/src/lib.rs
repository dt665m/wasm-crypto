use std::mem::size_of;
use std::mem::transmute;

use wasmtime::*;
use wasmtime_wasi::sync::WasiCtxBuilder;
use wasmtime_wasi::WasiCtx;

const WASM_CRYPTO: &[u8] = include_bytes!("./wasm_crypto.wasi.wasm");
// get output definitions
include!("../../../src/output.rs");

/// Wasmtime Host Container
pub struct WasmCrypto {
    store: Store<WasiCtx>,
    #[allow(dead_code)]
    engine: Engine,
    #[allow(dead_code)]
    linker: Linker<WasiCtx>,
    instance: Instance,
}

impl WasmCrypto {
    pub fn new() -> anyhow::Result<Self> {
        // An engine stores and configures global compilation settings like
        // optimization level, enabled wasm features, etc.
        let engine = Engine::default();
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

        // Create a WASI context and put it in a Store; all instances in the store
        // share this context. `WasiCtxBuilder` provides a number of ways to
        // configure what the target program will have access to.
        let wasi = WasiCtxBuilder::new()
            .inherit_stdio()
            // .inherit_args()?
            .build();

        let mut store = Store::new(&engine, wasi);
        let module = Module::new(&engine, WASM_CRYPTO)?;
        let instance = linker.instantiate(&mut store, &module)?;

        Ok(Self {
            store,
            engine,
            linker,
            instance,
        })
    }

    pub fn sign_secp256k1(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
        recoverable: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance
            .get_typed_func::<(i32, i32, i32, i32, i32), i32, _>(&mut store, "sign_secp256k1")?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let ret_ptr = func.call(
            &mut store,
            (
                secret_ptr,
                secret_len,
                msg_ptr,
                msg_len,
                if recoverable { 1 } else { 0 },
            ),
        )?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;

        Ok(res)
    }

    pub fn sign_keccak256_recoverable(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance.get_typed_func::<(i32, i32, i32, i32), i32, _>(
            &mut store,
            "sign_keccak256_secp256k1_recoverable",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let ret_ptr = func.call(&mut store, (secret_ptr, secret_len, msg_ptr, msg_len))?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;

        Ok(res)
    }

    pub fn xpriv_sign_secp256k1(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
        recoverable: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance.get_typed_func::<(i32, i32, i32, i32, i32), i32, _>(
            &mut store,
            "xpriv_sign_secp256k1",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let ret_ptr = func.call(
            &mut store,
            (
                secret_ptr,
                secret_len,
                msg_ptr,
                msg_len,
                if recoverable { 1 } else { 0 },
            ),
        )?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;

        Ok(res)
    }

    pub fn xpriv_child_sign_secp256k1(
        &mut self,
        secret_key: &[u8],
        message: &[u8],
        recoverable: bool,
        child_index: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance.get_typed_func::<(i32, i32, i32, i32, i32, i32), i32, _>(
            &mut store,
            "xpriv_child_sign_secp256k1",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let ret_ptr = func.call(
            &mut store,
            (
                secret_ptr,
                secret_len,
                msg_ptr,
                msg_len,
                if recoverable { 1 } else { 0 },
                child_index as i32,
            ),
        )?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;

        Ok(res)
    }

    pub fn public_key(&mut self, secret_key: &[u8], compressed: bool) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance
            .get_typed_func::<(i32, i32, i32), i32, _>(&mut store, "public_key_from_secret")?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;

        let ret_ptr = func.call(
            &mut store,
            (secret_ptr, secret_len, if compressed { 1 } else { 0 }),
        )?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;

        Ok(res)
    }

    pub fn public_key_xpriv(&mut self, xpriv: &[u8], compressed: bool) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let func = instance
            .get_typed_func::<(i32, i32, i32), i32, _>(&mut store, "public_key_from_xpriv")?;

        let secret_len = xpriv.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        memory.write(&mut store, secret_ptr as usize, xpriv)?;

        let ret_ptr = func.call(
            &mut store,
            (secret_ptr, secret_len, if compressed { 1 } else { 0 }),
        )?;
        // extracted results free itself
        let res = extract_result(store, &memory, &m_free, ret_ptr)?;

        // input can be freed
        m_free.call(&mut store, (secret_ptr, secret_len))?;

        Ok(res)
    }
}

/// Due to the rust compiler still having issues propagating +multivalue to `std`,
/// we are using a "struct container" to return complex types from the WASM runtime
/// https://github.com/rust-lang/rust/issues/73755
fn extract_result(
    store: &mut Store<WasiCtx>,
    memory: &Memory,
    m_free: &TypedFunc<(i32, i32), ()>,
    ret_ptr: i32,
) -> anyhow::Result<Vec<u8>> {
    let raw_vec_size = size_of::<RawVec>();
    let mut ret_buf = vec![0; raw_vec_size];
    memory.read(&mut *store, ret_ptr as usize, &mut ret_buf)?;
    let raw = unsafe { transmute::<*const u8, &RawVec>(ret_buf.as_ptr()) };

    let mut ret_buf = vec![0; raw.len as usize];
    memory.read(&mut *store, raw.ptr as usize, &mut ret_buf)?;

    // free the RawVec container
    m_free.call(&mut *store, (ret_ptr, raw_vec_size as i32))?;
    // free the Bytes referenced by RawVec
    m_free.call(&mut *store, (raw.ptr, raw.len))?;
    Ok(ret_buf)
}
