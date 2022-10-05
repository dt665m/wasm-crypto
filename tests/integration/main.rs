use wasm_crypto_rs::WasmCrypto;

use std::time::Instant;

use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    xkeys::Parent,
};
use k256::{
    ecdsa::{recoverable::Signature as RecoverableSignature, signature::DigestSigner, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
};

// #TODO Should use testing fixtures that are well-known.  Maybe from secp256k1 libraries on github
#[test]
fn it_can_create_signatures_with_wasm() {
    let signing_key_bytes =
        decode_hex("71ccdc13ab4775fc012763de2dfafa68bee9169cc27f06ab9107630d7c8f2992").unwrap();
    let xpriv_b58 =
        "xprv9s21ZrQH143K3fsbwbm3Q3JcUcd1VSJ2ukikDvzLaLpLbiy7buQqDAiw3LwoNp5RSjreg3G6aVTYa9MjVqAyocx3AjSNH4tgfoXiJftznyN";
    let xpriv_child_index = 1;
    println!("signing key bytes: {:?}", signing_key_bytes);
    let message = vec![0u8; 32];

    // #NOTE native sanity test
    let signing_key = SigningKey::from_bytes(&signing_key_bytes).unwrap();
    let sig = DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
        &signing_key,
        hash::Sha256Proxy::from(message.as_slice()),
    );
    let xpriv = MainnetEncoder::xpriv_from_base58(xpriv_b58).expect("decoding should succeed");
    let xpriv_signer: &SigningKey = xpriv.as_ref();
    let xpriv_sig = DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
        xpriv_signer,
        hash::Sha256Proxy::from(message.as_slice()),
    );
    let xpriv_child = xpriv.derive_child(xpriv_child_index).unwrap();
    let xpriv_child_b58 = MainnetEncoder::xpriv_to_base58(&xpriv_child).unwrap();
    println!("child_b58: {}", xpriv_child_b58);
    let xpriv_child_signer: &SigningKey = xpriv_child.as_ref();
    let xpriv_child_sig = DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
        xpriv_child_signer,
        hash::Sha256Proxy::from(message.as_slice()),
    );

    let now = Instant::now();
    let mut signer = WasmCrypto::new().unwrap();

    let wasm_sig = signer
        .sign_secp256k1(&signing_key_bytes, &message, true)
        .unwrap();
    let wasm_xpriv_sig = signer
        .xpriv_sign_secp256k1(xpriv_b58.as_bytes(), &message, true)
        .unwrap();
    let wasm_xpriv_child_sig = signer
        .xpriv_child_sign_secp256k1(
            xpriv_b58.as_bytes(),
            &message,
            true,
            xpriv_child_index as i32,
        )
        .unwrap();
    let wasm_pub = signer.public_key(&signing_key_bytes, false).unwrap();
    let wasm_pub_compressed = signer.public_key(&signing_key_bytes, true).unwrap();
    // Directly generate pubkey from a known Child XPriv
    let wasm_xpriv_pub = signer
        .public_key_xpriv(xpriv_child_b58.as_bytes(), false)
        .unwrap();
    let wasm_xpriv_pub_compressed = signer
        .public_key_xpriv(xpriv_child_b58.as_bytes(), true)
        .unwrap();
    // Generate pubkey from a Parent, generating the child in Wasm
    let wasm_xpriv_child_pub = signer
        .public_key_xpriv_child(xpriv_b58.as_bytes(), false, xpriv_child_index as i32)
        .unwrap();
    let wasm_xpriv_child_pub_compressed = signer
        .public_key_xpriv_child(xpriv_b58.as_bytes(), true, xpriv_child_index as i32)
        .unwrap();

    // stop timer
    let elapsed = now.elapsed();

    let verifying_key = signing_key.verifying_key();
    let verifying_key_uncomp = verifying_key.to_encoded_point(false);
    let verifying_key_comp = verifying_key.to_encoded_point(true);
    let verifying_key_child = xpriv_child_signer.verifying_key();
    let verifying_key_child_uncomp = verifying_key_child.to_encoded_point(false);
    let verifying_key_child_comp = verifying_key_child.to_encoded_point(true);

    assert_eq!(sig.as_ref().to_vec(), wasm_sig);
    assert_eq!(xpriv_sig.as_ref().to_vec(), wasm_xpriv_sig);
    assert_eq!(xpriv_child_sig.as_ref().to_vec(), wasm_xpriv_child_sig);
    assert_eq!(verifying_key_uncomp.as_ref(), wasm_pub);
    assert_eq!(verifying_key_comp.as_ref(), wasm_pub_compressed);
    assert_eq!(verifying_key_child_uncomp.as_ref(), wasm_xpriv_pub);
    assert_eq!(verifying_key_child_comp.as_ref(), wasm_xpriv_pub_compressed);
    assert_eq!(verifying_key_child_uncomp.as_ref(), wasm_xpriv_child_pub);
    assert_eq!(
        verifying_key_child_comp.as_ref(),
        wasm_xpriv_child_pub_compressed
    );

    //output for eyeball matching with go
    println!("wasm signature: {:?}", wasm_sig);
    println!("wasm xpriv signature: {:?}", wasm_xpriv_sig);
    println!("wasm xpriv child signature: {:?}", wasm_xpriv_child_sig);
    println!("public key: {:?}", wasm_pub);
    println!("public key length: {}", wasm_pub.len());
    println!("public key compressed: {:?}", wasm_pub_compressed);
    println!(
        "public key compressed length: {:?}",
        wasm_pub_compressed.len()
    );
    println!("xpriv child public key: {:?}", wasm_xpriv_pub);
    println!(
        "xpriv child public key compressed: {:?}",
        wasm_xpriv_pub_compressed
    );
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
