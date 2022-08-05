use wasm_signer::WasmSigner;

use k256::ecdsa::{
    recoverable::Signature as RecoverableSignature, signature::DigestSigner, SigningKey,
};

// #TODO Should use testing fixtures that are well-known.  Maybe from secp256k1 libraries on github
#[test]
fn it_can_create_signatures_with_wasm() {
    use std::time::Instant;
    let now = Instant::now();

    let message = vec![0u8; 32];
    let signing_key_bytes =
        decode_hex("71ccdc13ab4775fc012763de2dfafa68bee9169cc27f06ab9107630d7c8f2992").unwrap();

    let mut signer = WasmSigner::new().unwrap();
    let wasm_sig = signer
        .sign_recoverable(&signing_key_bytes, &message)
        .unwrap();

    // #NOTE native sanity test
    let signing_key = SigningKey::from_bytes(&signing_key_bytes).unwrap();
    let sig = DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
        &signing_key,
        hash::Sha256Proxy::from(message.as_slice()),
    );
    assert_eq!(sig.as_ref().to_vec(), wasm_sig);

    let elapsed = now.elapsed();
    println!("wasm signature: {:?}", wasm_sig);
    println!("elapsed: {:.2?}", elapsed);
}

use std::num::ParseIntError;
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

mod hash {
    //! This is a helper module used to pass the pre-hashed message for signing to the
    //! `sign_digest` methods of K256.
    use k256::ecdsa::signature::digest::{
        generic_array::GenericArray, Digest, FixedOutput, FixedOutputReset, HashMarker, Output,
        OutputSizeUser, Reset, Update,
    };

    pub type Sha256Proxy = ProxyDigest<sha2::Sha256>;

    #[derive(Clone)]
    pub enum ProxyDigest<D: Digest> {
        Proxy(Output<D>),
        Digest(D),
    }

    impl<D: Digest + Clone> From<&[u8]> for ProxyDigest<D>
    where
        GenericArray<u8, <D as OutputSizeUser>::OutputSize>: Copy,
    {
        fn from(src: &[u8]) -> Self {
            ProxyDigest::Proxy(*GenericArray::from_slice(src))
        }
    }

    impl<D: Digest> Default for ProxyDigest<D> {
        fn default() -> Self {
            ProxyDigest::Digest(D::new())
        }
    }

    impl<D: Digest> Update for ProxyDigest<D> {
        // we update only if we are digest
        fn update(&mut self, data: &[u8]) {
            match self {
                ProxyDigest::Digest(ref mut d) => {
                    d.update(data);
                }
                ProxyDigest::Proxy(..) => {
                    unreachable!("can not update if we are proxy");
                }
            }
        }
    }

    impl<D: Digest> HashMarker for ProxyDigest<D> {}

    impl<D: Digest> Reset for ProxyDigest<D> {
        // make new one
        fn reset(&mut self) {
            *self = Self::default();
        }
    }

    impl<D: Digest> OutputSizeUser for ProxyDigest<D> {
        // we default to the output of the original digest
        type OutputSize = <D as OutputSizeUser>::OutputSize;
    }

    impl<D: Digest> FixedOutput for ProxyDigest<D> {
        fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
            match self {
                ProxyDigest::Digest(d) => {
                    *out = d.finalize();
                }
                ProxyDigest::Proxy(p) => {
                    *out = p;
                }
            }
        }
    }

    impl<D: Digest> FixedOutputReset for ProxyDigest<D> {
        fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
            let s = std::mem::take(self);
            Digest::finalize_into(s, out)
        }
    }
}
