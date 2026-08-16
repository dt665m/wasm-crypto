use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    xkeys::Parent,
};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha3::{Digest, Keccak256};
use wasm_crypto_rs::WasmCrypto;

const SECRET_KEY_HEX: &str = "71ccdc13ab4775fc012763de2dfafa68bee9169cc27f06ab9107630d7c8f2992";
const XPRIV: &str = "xprv9s21ZrQH143K3fsbwbm3Q3JcUcd1VSJ2ukikDvzLaLpLbiy7buQqDAiw3LwoNp5RSjreg3G6aVTYa9MjVqAyocx3AjSNH4tgfoXiJftznyN";

#[test]
fn wasm_crypto_matches_native_secp256k1_and_bip32() {
    let secret_key = decode_hex(SECRET_KEY_HEX).expect("valid secret-key fixture");
    let message = [0_u8; 32];
    let child_index = 1;
    let direct_key = SigningKey::from_slice(&secret_key).expect("valid secp256k1 key");

    let xpriv = MainnetEncoder::xpriv_from_base58(XPRIV).expect("valid xpriv fixture");
    let xpriv_key = signing_key_from_xpriv(&xpriv);
    let child_xpriv = xpriv
        .derive_child(child_index)
        .expect("valid BIP32 child index");
    let child_key = signing_key_from_xpriv(&child_xpriv);
    let child_xpriv_b58 =
        MainnetEncoder::xpriv_to_base58(&child_xpriv).expect("encodable child xpriv");

    let mut wasm = WasmCrypto::new().expect("instantiate wasm crypto");

    assert_eq!(
        recoverable_signature(&direct_key, &message),
        wasm.sign_secp256k1(&secret_key, &message, true)
            .expect("wasm direct recoverable signature")
    );
    assert_eq!(
        der_signature(&direct_key, &message),
        wasm.sign_secp256k1(&secret_key, &message, false)
            .expect("wasm direct DER signature")
    );
    assert_eq!(
        recoverable_signature(&xpriv_key, &message),
        wasm.xpriv_sign_secp256k1(XPRIV.as_bytes(), &message, true)
            .expect("wasm xpriv signature")
    );
    assert_eq!(
        recoverable_signature(&child_key, &message),
        wasm.xpriv_child_sign_secp256k1(XPRIV.as_bytes(), &message, true, child_index as i32)
            .expect("wasm child xpriv signature")
    );

    assert_eq!(
        direct_key.verifying_key().to_sec1_point(false).as_bytes(),
        wasm.public_key(&secret_key, false)
            .expect("wasm uncompressed public key")
    );
    assert_eq!(
        direct_key.verifying_key().to_sec1_point(true).as_bytes(),
        wasm.public_key(&secret_key, true)
            .expect("wasm compressed public key")
    );
    assert_eq!(
        child_key.verifying_key().to_sec1_point(false).as_bytes(),
        wasm.public_key_xpriv(child_xpriv_b58.as_bytes(), false)
            .expect("wasm xpriv public key")
    );
    assert_eq!(
        child_key.verifying_key().to_sec1_point(true).as_bytes(),
        wasm.public_key_xpriv_child(XPRIV.as_bytes(), true, child_index as i32)
            .expect("wasm child xpriv public key")
    );

    let raw_message = b"wasm crypto Keccak-256 test";
    let keccak_digest = Keccak256::digest(raw_message);
    assert_eq!(
        recoverable_signature(&direct_key, &keccak_digest),
        wasm.sign_keccak256_recoverable(&secret_key, raw_message)
            .expect("wasm Keccak-256 signature")
    );

    assert!(wasm.sign_secp256k1(&secret_key, &[0; 31], true).is_err());
    assert!(wasm
        .xpriv_child_sign_secp256k1(XPRIV.as_bytes(), &message, true, -1)
        .is_err());
}

fn signing_key_from_xpriv(xpriv: &coins_bip32::xkeys::XPriv) -> SigningKey {
    let source_key: &coins_bip32::prelude::k256::ecdsa::SigningKey = xpriv.as_ref();
    SigningKey::from_slice(source_key.to_bytes().as_slice()).expect("xpriv contains valid key")
}

fn recoverable_signature(signing_key: &SigningKey, prehash: &[u8]) -> Vec<u8> {
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(prehash);
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(recovery_id.to_byte());
    encoded
}

fn der_signature(signing_key: &SigningKey, prehash: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign_prehash(prehash).expect("32-byte prehash");
    signature.to_der().as_bytes().to_vec()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16))
        .collect()
}
