use wasmtime::*;
use wasmtime_wasi::sync::WasiCtxBuilder;
use wasmtime_wasi::WasiCtx;

const WASM_CRYPTO: &[u8] = include_bytes!("./wasm_crypto.wasi.wasm");

/// Wasmtime Host Container
pub struct WasmSigner {
    store: Store<WasiCtx>,
    #[allow(dead_code)]
    engine: Engine,
    #[allow(dead_code)]
    linker: Linker<WasiCtx>,
    instance: Instance,
}

impl WasmSigner {
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

    pub fn sign_recoverable(
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
        let sign_func = instance.get_typed_func::<(i32, i32, i32, i32), (i32, i32), _>(
            &mut store,
            "sign_secp256k1_recoverable",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let (ret_ptr, ret_len) =
            sign_func.call(&mut store, (secret_ptr, secret_len, msg_ptr, msg_len))?;
        let mut ret_buf = vec![0; ret_len as usize];
        memory.read(&mut store, ret_ptr as usize, &mut ret_buf)?;

        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;
        m_free.call(&mut store, (ret_ptr, ret_len))?;

        Ok(ret_buf)
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
        let sign_func = instance.get_typed_func::<(i32, i32, i32, i32), (i32, i32), _>(
            &mut store,
            "sign_keccak256_secp256k1_recoverable",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let (ret_ptr, ret_len) =
            sign_func.call(&mut store, (secret_ptr, secret_len, msg_ptr, msg_len))?;
        let mut ret_buf = vec![0; ret_len as usize];
        memory.read(&mut store, ret_ptr as usize, &mut ret_buf)?;

        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;
        m_free.call(&mut store, (ret_ptr, ret_len))?;

        Ok(ret_buf)
    }

    pub fn sign_to_der(&mut self, secret_key: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut store = &mut self.store;
        let instance = &self.instance;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(anyhow::anyhow!("memory not found"))?;

        let m_alloc = instance.get_typed_func::<i32, i32, _>(&mut store, "m_alloc")?;
        let m_free = instance.get_typed_func::<(i32, i32), (), _>(&mut store, "m_free")?;
        let sign_func = instance.get_typed_func::<(i32, i32, i32, i32), (i32, i32), _>(
            &mut store,
            "sign_secp256k1_to_der",
        )?;

        let secret_len = secret_key.len() as i32;
        let secret_ptr = m_alloc.call(&mut store, secret_len as i32)?;
        let msg_len = message.len() as i32;
        let msg_ptr = m_alloc.call(&mut store, message.len() as i32)?;
        memory.write(&mut store, secret_ptr as usize, secret_key)?;
        memory.write(&mut store, msg_ptr as usize, message)?;

        let (ret_ptr, ret_len) =
            sign_func.call(&mut store, (secret_ptr, secret_len, msg_ptr, msg_len))?;
        let mut ret_buf = vec![0; ret_len as usize];
        memory.read(&mut store, ret_ptr as usize, &mut ret_buf)?;

        m_free.call(&mut store, (secret_ptr, secret_len))?;
        m_free.call(&mut store, (msg_ptr, msg_ptr))?;
        m_free.call(&mut store, (ret_ptr, ret_len))?;

        Ok(ret_buf)
    }
}
