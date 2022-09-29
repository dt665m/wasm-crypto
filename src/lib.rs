//! Secp256k1 signatures exposed as C FFI for WASM or any other C FFI bindings
mod output;
use output::*;

use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    xkeys::Parent,
};

use k256::{
    ecdsa::{
        recoverable::Signature as RecoverableSignature,
        signature::{DigestSigner, Signer},
        Signature, SigningKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub unsafe fn m_alloc(len: usize) -> *mut u8 {
    let align = std::mem::align_of::<usize>();
    let layout = Layout::from_size_align_unchecked(len, align);
    alloc(layout)
}

#[no_mangle]
pub unsafe fn m_free(ptr: *mut u8, size: usize) {
    let align = std::mem::align_of::<usize>();
    let layout = Layout::from_size_align_unchecked(size, align);
    dealloc(ptr, layout);
}

/// Secp256k1 signature.  Assumes payload is pre-hashed.
/// Recoverable signature is encoded in ASN.1 DER
#[no_mangle]
pub unsafe fn sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
) -> *const RawVec {
    let (key_bytes, msg_bytes) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let signing_key =
        SigningKey::from_bytes(key_bytes.as_slice()).expect("key should be valid. qed");
    to_raw(secp256k1_sign_inner(
        &signing_key,
        &msg_bytes,
        if recoverable != 0 { true } else { false },
    ))
}

/// Secp256k1 recoverable signature.  Hashing is done on the message using
/// Keccak256.  A raw RLP Ethereum transaction can be used as message
#[no_mangle]
pub unsafe fn sign_keccak256_secp256k1_recoverable(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> *const RawVec {
    let (key_bytes, msg_bytes) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let signing_key =
        SigningKey::from_bytes(key_bytes.as_slice()).expect("key should be valid. qed");
    let sig: RecoverableSignature = signing_key.sign(msg_bytes.as_slice());
    to_raw(sig.as_ref().to_vec())
}

/// XPriv Sign
#[no_mangle]
pub fn xpriv_sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
) -> *const RawVec {
    let (xpriv_bytes, msg_bytes) = unsafe { parse_input(pk_ptr, pk_len, msg_ptr, msg_len) };
    let xpriv = unsafe {
        MainnetEncoder::xpriv_from_base58(std::str::from_utf8_unchecked(&xpriv_bytes))
            .expect("decoding should succeed")
    };

    to_raw(secp256k1_sign_inner(
        xpriv.as_ref(),
        &msg_bytes,
        if recoverable != 0 { true } else { false },
    ))
}

/// XPriv Sign with Derivation Child Index
#[no_mangle]
pub fn xpriv_child_sign_secp256k1(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
    recoverable: usize,
    child_index: usize,
) -> *const RawVec {
    let (xpriv_bytes, msg_bytes) = unsafe { parse_input(pk_ptr, pk_len, msg_ptr, msg_len) };
    let xpriv = unsafe {
        MainnetEncoder::xpriv_from_base58(std::str::from_utf8_unchecked(&xpriv_bytes))
            .expect("decoding should succeed")
    };
    let xpriv = xpriv
        .derive_child(child_index as u32)
        .expect("child_index should be valid");

    to_raw(secp256k1_sign_inner(
        xpriv.as_ref(),
        &msg_bytes,
        if recoverable != 0 { true } else { false },
    ))
}

/// Secp256k1 public key bytes from SecretKey
#[no_mangle]
pub fn public_key_from_secret(pk_ptr: *mut u8, pk_len: usize, compressed: usize) -> *const RawVec {
    let signing_key = unsafe {
        SigningKey::from_bytes(Vec::from_raw_parts(pk_ptr, pk_len, pk_len).as_slice())
            .expect("key should be valid. qed")
    };
    let verifying_key = signing_key.verifying_key();
    let verifying_key = verifying_key.to_encoded_point(compressed > 0);
    to_raw(verifying_key.as_bytes().to_vec())
}

/// Secp256k1 public key bytes from XPriv
#[no_mangle]
pub fn public_key_from_xpriv(pk_ptr: *mut u8, pk_len: usize, compressed: usize) -> *const RawVec {
    let xpriv = unsafe {
        let xpriv_bytes = Vec::from_raw_parts(pk_ptr, pk_len, pk_len);
        MainnetEncoder::xpriv_from_base58(std::str::from_utf8_unchecked(&xpriv_bytes))
            .expect("decoding should succeed")
    };
    let signing_key: &SigningKey = xpriv.as_ref();
    let verifying_key = signing_key.verifying_key();
    let verifying_key = verifying_key.to_encoded_point(compressed > 0);
    to_raw(verifying_key.as_bytes().to_vec())
}

/// Recoverable = Ethereum Style Signature
/// !Recoverable = Bitcoin Style Signature (`der` encoded)
#[inline]
fn secp256k1_sign_inner(signing_key: &SigningKey, message: &[u8], recoverable: bool) -> Vec<u8> {
    if recoverable {
        DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
            signing_key,
            hash::Sha256Proxy::from(message),
        )
        .as_ref()
        .to_vec()
    } else {
        DigestSigner::<hash::Sha256Proxy, Signature>::sign_digest(
            signing_key,
            hash::Sha256Proxy::from(message),
        )
        .to_der()
        .as_ref()
        .to_vec()
    }
}

/// By default we usually have a key input and msg input
#[inline]
unsafe fn parse_input(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    (
        Vec::from_raw_parts(pk_ptr, pk_len, pk_len),
        Vec::from_raw_parts(msg_ptr, msg_len, msg_len),
    )
}

/// We use C memory layout "serialization" to respond back to the host
#[inline]
fn to_raw(mut data: Vec<u8>) -> *const RawVec {
    let ret_len = data.len();
    let ptr = data.as_mut_ptr();

    // need to force a heap allocation to write into the linear wasm memory
    let result = Box::new(RawVec {
        ptr: ptr as i32,
        len: ret_len as i32,
    });
    // leak the box into a `ptr`
    let ret = Box::into_raw(result) as *const RawVec;

    // leak pointer so memory isn't dropped when out of scope
    // `ptr` must be freed by the host caller
    std::mem::forget(data);
    ret
}

mod hash {
    //! This is a helper module used to pass the pre-hashed message for signing to the
    //! `sign_digest` methods of K256.
    use coins_bip32::prelude::k256::ecdsa::signature::digest::{
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
