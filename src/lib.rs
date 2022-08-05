//! Secp256k1 signatures exposed as C FFI for WASM or any other C FFI bindings

use k256::ecdsa::{
    recoverable::Signature as RecoverableSignature,
    signature::{DigestSigner, Signer},
    Signature, SigningKey,
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

/// Secp256k1 recoverable signature.  Assumes payload is pre-hashed
#[no_mangle]
pub unsafe fn sign_secp256k1_recoverable(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (*mut u8, usize) {
    let (signing_key, message) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let sig = DigestSigner::<hash::Sha256Proxy, RecoverableSignature>::sign_digest(
        &signing_key,
        hash::Sha256Proxy::from(message.as_slice()),
    );
    to_output(sig.as_ref().to_vec())
}

/// Secp256k1 recoverable signature.  Hashing is done on the message using
/// Keccak256.  A raw RLP Ethereum transaction can be used as message
#[no_mangle]
pub unsafe fn sign_keccak256_secp256k1_recoverable(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (*mut u8, usize) {
    let (signing_key, message) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let sig: RecoverableSignature = signing_key.sign(message.as_slice());
    to_output(sig.as_ref().to_vec())
}

/// Secp256k1 signature encoded in ASN.1 DER.  Assumes payload is pre-hashed
#[no_mangle]
pub unsafe fn sign_secp256k1_to_der(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (*mut u8, usize) {
    let (signing_key, message) = parse_input(pk_ptr, pk_len, msg_ptr, msg_len);
    let sig = DigestSigner::<hash::Sha256Proxy, Signature>::sign_digest(
        &signing_key,
        hash::Sha256Proxy::from(message.as_slice()),
    );
    to_output(sig.to_der().as_ref().to_vec())
}

#[inline]
unsafe fn parse_input(
    pk_ptr: *mut u8,
    pk_len: usize,
    msg_ptr: *mut u8,
    msg_len: usize,
) -> (SigningKey, Vec<u8>) {
    (
        SigningKey::from_bytes(Vec::from_raw_parts(pk_ptr, pk_len, pk_len).as_slice())
            .expect("key should be valid. qed"),
        Vec::from_raw_parts(msg_ptr, msg_len, msg_len),
    )
}

#[inline]
fn to_output(mut sig_bytes: Vec<u8>) -> (*mut u8, usize) {
    let ret_len = sig_bytes.len();
    let ptr = sig_bytes.as_mut_ptr();
    // leak pointer so memory isn't dropped when out of scope
    // `ptr` must be freed by the host caller
    std::mem::forget(sig_bytes);
    (ptr, ret_len)
}

pub fn respond_error(err_message: String) -> (*mut u8, usize) {
    let mut err_msg = err_message.to_string().into_bytes();
    let ptr = err_msg.as_mut_ptr();
    let err_msg_len = err_msg.len();
    std::mem::forget(err_msg);
    (ptr, err_msg_len)
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
