//! Secp256k1 signatures exposed as C FFI for WASM or any other C FFI bindings
mod output;
use output::RawVec;

use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    xkeys::Parent,
};

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha3::{Digest, Keccak256};
use std::{
    alloc::{alloc, dealloc, Layout},
    mem::size_of,
    ptr, slice,
};

const SECP256K1_PREHASH_LEN: usize = 32;

/// Allocates a byte buffer in the guest's linear memory.
///
/// # Safety
///
/// The returned pointer must be released exactly once with [`m_free`] using
/// the same `len`. Callers must not read or write past the allocated buffer.
#[no_mangle]
pub unsafe fn m_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return ptr::NonNull::dangling().as_ptr();
    }

    let layout = Layout::array::<u8>(len).expect("allocation size should fit in address space");
    alloc(layout)
}

/// Releases a byte buffer obtained from [`m_alloc`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by [`m_alloc`] and `size` must be the
/// exact length passed to that allocation. The buffer must not be used after
/// this call.
#[no_mangle]
pub unsafe fn m_free(ptr: *mut u8, size: usize) {
    if size == 0 {
        return;
    }

    let layout = Layout::array::<u8>(size).expect("allocation size should fit in address space");
    dealloc(ptr, layout);
}

/// Secp256k1 signature.  Assumes payload is pre-hashed.
/// Recoverable signatures are encoded as r||s||recovery-ID; other signatures
/// use ASN.1 DER.
///
/// # Safety
///
/// `pk_ptr` and `msg_ptr` must point to readable guest-memory buffers of
/// `pk_len` and `msg_len` bytes respectively for the duration of this call.
#[no_mangle]
pub unsafe fn sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
) -> *const RawVec {
    let (key_bytes, msg_bytes) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let signing_key = SigningKey::from_slice(key_bytes).expect("key should be valid");
    to_raw(secp256k1_sign_inner(
        &signing_key,
        msg_bytes,
        recoverable != 0,
    ))
}

/// Secp256k1 recoverable signature.  Hashing is done on the message using
/// Keccak256.  A raw RLP Ethereum transaction can be used as message
///
/// # Safety
///
/// `pk_ptr` and `msg_ptr` must point to readable guest-memory buffers of
/// `pk_len` and `msg_len` bytes respectively for the duration of this call.
#[no_mangle]
pub unsafe fn sign_keccak256_secp256k1_recoverable(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> *const RawVec {
    let (key_bytes, msg_bytes) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let signing_key = SigningKey::from_slice(key_bytes).expect("key should be valid");
    let digest = Keccak256::digest(msg_bytes);
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest);
    to_raw(recoverable_signature_bytes(
        signature,
        recovery_id.to_byte(),
    ))
}

/// XPriv Sign
///
/// # Safety
///
/// `pk_ptr` and `msg_ptr` must point to readable guest-memory buffers of
/// `pk_len` and `msg_len` bytes respectively for the duration of this call.
#[no_mangle]
pub unsafe fn xpriv_sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
) -> *const RawVec {
    let (xpriv_bytes, msg_bytes) = unsafe { parse_input(pk_ptr, pk_len, msg_ptr, msg_len) };
    let xpriv = decode_xpriv(xpriv_bytes);
    let signing_key = signing_key_from_xpriv(&xpriv);

    to_raw(secp256k1_sign_inner(
        &signing_key,
        msg_bytes,
        recoverable != 0,
    ))
}

/// XPriv Sign with Derivation Child Index
///
/// # Safety
///
/// `pk_ptr` and `msg_ptr` must point to readable guest-memory buffers of
/// `pk_len` and `msg_len` bytes respectively for the duration of this call.
#[no_mangle]
pub unsafe fn xpriv_child_sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
    child_index: usize,
) -> *const RawVec {
    let (xpriv_bytes, msg_bytes) = unsafe { parse_input(pk_ptr, pk_len, msg_ptr, msg_len) };
    let xpriv = decode_xpriv(xpriv_bytes);
    let xpriv = xpriv
        .derive_child(child_index as u32)
        .expect("child index should be valid");
    let signing_key = signing_key_from_xpriv(&xpriv);

    to_raw(secp256k1_sign_inner(
        &signing_key,
        msg_bytes,
        recoverable != 0,
    ))
}

/// Secp256k1 public key bytes from SecretKey
///
/// # Safety
///
/// `pk_ptr` must point to a readable guest-memory buffer of `pk_len` bytes
/// for the duration of this call.
#[no_mangle]
pub unsafe fn public_key_from_secret(
    pk_ptr: *mut u8,
    pk_len: usize,
    compressed: usize,
) -> *const RawVec {
    let key_bytes = unsafe { input_slice(pk_ptr, pk_len) };
    let signing_key = SigningKey::from_slice(key_bytes).expect("key should be valid");
    let verifying_key = signing_key.verifying_key();
    let verifying_key = verifying_key.to_sec1_point(compressed > 0);
    to_raw(verifying_key.as_bytes().to_vec())
}

/// Secp256k1 public key bytes from XPriv
///
/// # Safety
///
/// `pk_ptr` must point to a readable guest-memory buffer of `pk_len` bytes
/// for the duration of this call.
#[no_mangle]
pub unsafe fn public_key_from_xpriv(
    pk_ptr: *mut u8,
    pk_len: usize,
    compressed: usize,
) -> *const RawVec {
    let xpriv_bytes = unsafe { input_slice(pk_ptr, pk_len) };
    let xpriv = decode_xpriv(xpriv_bytes);
    let signing_key = signing_key_from_xpriv(&xpriv);
    let verifying_key = signing_key.verifying_key();
    let verifying_key = verifying_key.to_sec1_point(compressed > 0);
    to_raw(verifying_key.as_bytes().to_vec())
}

/// Secp256k1 public key bytes from XPriv Child
///
/// # Safety
///
/// `pk_ptr` must point to a readable guest-memory buffer of `pk_len` bytes
/// for the duration of this call.
#[no_mangle]
pub unsafe fn public_key_from_xpriv_child(
    pk_ptr: *mut u8,
    pk_len: usize,
    compressed: usize,
    child_index: usize,
) -> *const RawVec {
    let xpriv_bytes = unsafe { input_slice(pk_ptr, pk_len) };
    let xpriv = decode_xpriv(xpriv_bytes)
        .derive_child(child_index as u32)
        .expect("child index should be valid");
    let signing_key = signing_key_from_xpriv(&xpriv);
    let verifying_key = signing_key.verifying_key();
    let verifying_key = verifying_key.to_sec1_point(compressed > 0);
    to_raw(verifying_key.as_bytes().to_vec())
}

/// Recoverable = Ethereum Style Signature
/// !Recoverable = Bitcoin Style Signature (`der` encoded)
#[inline]
fn secp256k1_sign_inner(signing_key: &SigningKey, message: &[u8], recoverable: bool) -> Vec<u8> {
    assert_eq!(
        message.len(),
        SECP256K1_PREHASH_LEN,
        "message should be a 32-byte secp256k1 prehash"
    );

    if recoverable {
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(message);
        recoverable_signature_bytes(signature, recovery_id.to_byte())
    } else {
        let signature: Signature = signing_key
            .sign_prehash(message)
            .expect("message should be a valid secp256k1 prehash");
        signature.to_der().as_bytes().to_vec()
    }
}

#[inline]
fn recoverable_signature_bytes(signature: Signature, recovery_id: u8) -> Vec<u8> {
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(recovery_id);
    encoded
}

#[inline]
fn decode_xpriv(xpriv_bytes: &[u8]) -> coins_bip32::xkeys::XPriv {
    let xpriv = std::str::from_utf8(xpriv_bytes).expect("xpriv should be valid UTF-8");
    MainnetEncoder::xpriv_from_base58(xpriv).expect("xpriv should be valid base58")
}

#[inline]
fn signing_key_from_xpriv(xpriv: &coins_bip32::xkeys::XPriv) -> SigningKey {
    let source_key: &coins_bip32::prelude::k256::ecdsa::SigningKey = xpriv.as_ref();
    SigningKey::from_slice(source_key.to_bytes().as_slice())
        .expect("xpriv should contain a valid secp256k1 signing key")
}

/// By default we usually have a key input and msg input
#[inline]
unsafe fn parse_input<'a>(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (&'a [u8], &'a [u8]) {
    (input_slice(pk_ptr, pk_len), input_slice(msg_ptr, msg_len))
}

#[inline]
unsafe fn input_slice<'a>(ptr: *mut u8, len: usize) -> &'a [u8] {
    slice::from_raw_parts(ptr, len)
}

/// We use C memory layout "serialization" to respond back to the host
#[inline]
fn to_raw(data: Vec<u8>) -> *const RawVec {
    let data = data.into_boxed_slice();
    let data_len = i32::try_from(data.len()).expect("output should fit in wasm32 memory");
    let data_ptr = Box::into_raw(data) as *mut u8;

    let descriptor_ptr = unsafe { m_alloc(size_of::<RawVec>()) };
    let descriptor = RawVec {
        ptr: data_ptr as i32,
        len: data_len,
    };
    unsafe {
        ptr::copy_nonoverlapping(
            (&descriptor as *const RawVec).cast::<u8>(),
            descriptor_ptr,
            size_of::<RawVec>(),
        );
    }
    descriptor_ptr.cast::<RawVec>()
}
