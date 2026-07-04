#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::needless_range_loop)]

use crate::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use core::slice;

const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
const MLDSA87_PRIVATE_KEY_BYTES: usize = 4896;
const MLDSA87_SIGNATURE_BYTES: usize = 4627;
const HYBRID_ECC_KEY_BYTES: usize = 32;
const HYBRID_PQC_PUBLIC_KEY_BYTES: usize = 1184;
const HYBRID_PQC_PRIVATE_KEY_BYTES: usize = 2400;
const HYBRID_PQC_CIPHERTEXT_BYTES: usize = 1088;
const AES_GCM_IV_BYTES: usize = 12;
const AES_GCM_TAG_BYTES: usize = 16;

unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

unsafe fn fixed_input<'a, const N: usize>(ptr: *const u8) -> Option<&'a [u8; N]> {
    if ptr.is_null() {
        None
    } else {
        Some(&*(ptr as *const [u8; N]))
    }
}

unsafe fn zero_output(ptr: *mut u8, len: usize) {
    if len != 0 && !ptr.is_null() {
        core::ptr::write_bytes(ptr, 0, len);
    }
}

/// # Safety
/// All pointer arguments must be valid, non-null, and point to allocated memory of the
/// specified lengths. The caller is responsible for ensuring all buffers are large enough.

#[no_mangle]
pub unsafe extern "C" fn mldsa87_generate_keypair(
    entropy_ptr: *const u8,
    pub_key_out: *mut u8,
    pub_key_len: usize,
    priv_key_out: *mut u8,
    priv_key_len: usize,
) -> i32 {
    if pub_key_len < MLDSA87_PUBLIC_KEY_BYTES || priv_key_len < MLDSA87_PRIVATE_KEY_BYTES {
        return -1;
    }
    if entropy_ptr.is_null() || pub_key_out.is_null() || priv_key_out.is_null() {
        return -1;
    }
    let entropy = match fixed_input::<32>(entropy_ptr) {
        Some(entropy) => entropy,
        None => return -1,
    };
    let (pk, sk) = ml_dsa_87_keypair(entropy);
    core::ptr::copy_nonoverlapping(pk.as_ptr(), pub_key_out, pk.len());
    core::ptr::copy_nonoverlapping(sk.as_ptr(), priv_key_out, sk.len());
    0
}

#[no_mangle]
pub unsafe extern "C" fn mldsa87_sign(
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    rnd_ptr: *const u8,
    priv_key_ptr: *const u8,
    sig_out: *mut u8,
    sig_out_len: usize,
) -> i32 {
    if sig_out_len < MLDSA87_SIGNATURE_BYTES {
        return -1;
    }
    if priv_key_ptr.is_null() || sig_out.is_null() || rnd_ptr.is_null() {
        return -1;
    }
    let msg = match input_slice(msg_ptr, msg_len) {
        Some(msg) => msg,
        None => {
            zero_output(sig_out, MLDSA87_SIGNATURE_BYTES);
            return -1;
        }
    };
    let ctx = match input_slice(ctx_ptr, ctx_len) {
        Some(ctx) => ctx,
        None => {
            zero_output(sig_out, MLDSA87_SIGNATURE_BYTES);
            return -1;
        }
    };
    let rnd = match fixed_input::<32>(rnd_ptr) {
        Some(rnd) => rnd,
        None => {
            zero_output(sig_out, MLDSA87_SIGNATURE_BYTES);
            return -1;
        }
    };
    let sk_slice = slice::from_raw_parts(priv_key_ptr, MLDSA87_PRIVATE_KEY_BYTES);

    match ml_dsa_87_sign(sk_slice, msg, ctx, rnd) {
        Ok(sig) => {
            core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, sig.len());
            0
        }
        Err(_) => {
            zero_output(sig_out, MLDSA87_SIGNATURE_BYTES);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mldsa87_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    ctx_ptr: *const u8,
    ctx_len: usize,
    sig_ptr: *const u8,
    pub_key_ptr: *const u8,
) -> i32 {
    if sig_ptr.is_null() || pub_key_ptr.is_null() {
        return 0;
    }
    let msg = match input_slice(msg_ptr, msg_len) {
        Some(msg) => msg,
        None => return 0,
    };
    let ctx = match input_slice(ctx_ptr, ctx_len) {
        Some(ctx) => ctx,
        None => return 0,
    };
    let sig = slice::from_raw_parts(sig_ptr, MLDSA87_SIGNATURE_BYTES);
    let pk = slice::from_raw_parts(pub_key_ptr, MLDSA87_PUBLIC_KEY_BYTES);

    if ml_dsa_87_verify(pk, msg, ctx, sig) {
        1
    } else {
        0
    }
}

use crate::{hybrid_decrypt_payload, hybrid_encrypt_payload, HybridKeyPair};

#[no_mangle]
pub unsafe extern "C" fn hybrid_generate_keypair(
    entropy_ecc_ptr: *const u8,
    entropy_pqc_ptr: *const u8,
    ecc_priv_out: *mut u8,
    ecc_priv_len: usize,
    ecc_pub_out: *mut u8,
    ecc_pub_len: usize,
    pqc_priv_out: *mut u8,
    pqc_priv_len: usize,
    pqc_pub_out: *mut u8,
    pqc_pub_len: usize,
) -> i32 {
    if ecc_priv_len < HYBRID_ECC_KEY_BYTES
        || ecc_pub_len < HYBRID_ECC_KEY_BYTES
        || pqc_priv_len < HYBRID_PQC_PRIVATE_KEY_BYTES
        || pqc_pub_len < HYBRID_PQC_PUBLIC_KEY_BYTES
    {
        return -1;
    }
    if entropy_ecc_ptr.is_null()
        || entropy_pqc_ptr.is_null()
        || ecc_priv_out.is_null()
        || ecc_pub_out.is_null()
        || pqc_priv_out.is_null()
        || pqc_pub_out.is_null()
    {
        return -1;
    }
    let entropy_ecc = match fixed_input::<32>(entropy_ecc_ptr) {
        Some(entropy) => entropy,
        None => return -1,
    };
    let entropy_pqc = match fixed_input::<64>(entropy_pqc_ptr) {
        Some(entropy) => entropy,
        None => return -1,
    };
    let kp = HybridKeyPair::generate(entropy_ecc, entropy_pqc);

    core::ptr::copy_nonoverlapping(kp.ecc_private.as_ptr(), ecc_priv_out, HYBRID_ECC_KEY_BYTES);
    core::ptr::copy_nonoverlapping(kp.ecc_public.as_ptr(), ecc_pub_out, HYBRID_ECC_KEY_BYTES);
    core::ptr::copy_nonoverlapping(
        kp.pqc_private.as_ptr(),
        pqc_priv_out,
        HYBRID_PQC_PRIVATE_KEY_BYTES,
    );
    core::ptr::copy_nonoverlapping(
        kp.pqc_public.as_ptr(),
        pqc_pub_out,
        HYBRID_PQC_PUBLIC_KEY_BYTES,
    );
    0
}

#[no_mangle]
pub unsafe extern "C" fn hybrid_encrypt(
    payload_ptr: *const u8,
    payload_len: usize,
    ecc_pub_ptr: *const u8,
    pqc_pub_ptr: *const u8,
    entropy_ecc_ptr: *const u8,
    entropy_pqc_ptr: *const u8,
    iv_ptr: *const u8,
    ciphertext_out: *mut u8,
    iv_out: *mut u8,
    tag_out: *mut u8,
    ecc_ephem_out: *mut u8,
    pqc_cipher_out: *mut u8,
    ciphertext_out_len: usize,
) -> i32 {
    if ciphertext_out_len < payload_len {
        return -1;
    }
    if ecc_pub_ptr.is_null()
        || pqc_pub_ptr.is_null()
        || entropy_ecc_ptr.is_null()
        || entropy_pqc_ptr.is_null()
        || iv_ptr.is_null()
        || (payload_len != 0 && payload_ptr.is_null())
        || (payload_len != 0 && ciphertext_out.is_null())
        || iv_out.is_null()
        || tag_out.is_null()
        || ecc_ephem_out.is_null()
        || pqc_cipher_out.is_null()
    {
        return -1;
    }
    let payload = match input_slice(payload_ptr, payload_len) {
        Some(payload) => payload,
        None => return -1,
    };
    let peer_ecc_pub = match fixed_input::<32>(ecc_pub_ptr) {
        Some(peer_ecc_pub) => peer_ecc_pub,
        None => return -1,
    };
    let peer_pqc_pub = match fixed_input::<1184>(pqc_pub_ptr) {
        Some(peer_pqc_pub) => peer_pqc_pub,
        None => return -1,
    };
    let entropy_ecc = match fixed_input::<32>(entropy_ecc_ptr) {
        Some(entropy_ecc) => entropy_ecc,
        None => return -1,
    };
    let entropy_pqc = match fixed_input::<32>(entropy_pqc_ptr) {
        Some(entropy_pqc) => entropy_pqc,
        None => return -1,
    };
    let iv = match fixed_input::<12>(iv_ptr) {
        Some(iv) => iv,
        None => return -1,
    };

    match hybrid_encrypt_payload(
        payload,
        peer_ecc_pub,
        peer_pqc_pub,
        entropy_ecc,
        entropy_pqc,
        iv,
    ) {
        Ok(package) => {
            if payload_len != 0 {
                core::ptr::copy_nonoverlapping(
                    package.ciphertext.as_ptr(),
                    ciphertext_out,
                    payload_len,
                );
            }
            core::ptr::copy_nonoverlapping(package.iv.as_ptr(), iv_out, AES_GCM_IV_BYTES);
            core::ptr::copy_nonoverlapping(package.tag.as_ptr(), tag_out, AES_GCM_TAG_BYTES);
            core::ptr::copy_nonoverlapping(
                package.ecc_ephemeral_pub.as_ptr(),
                ecc_ephem_out,
                HYBRID_ECC_KEY_BYTES,
            );
            core::ptr::copy_nonoverlapping(
                package.pqc_ciphertext.as_ptr(),
                pqc_cipher_out,
                HYBRID_PQC_CIPHERTEXT_BYTES,
            );
            0
        }
        Err(_) => {
            zero_output(ciphertext_out, ciphertext_out_len);
            zero_output(iv_out, AES_GCM_IV_BYTES);
            zero_output(tag_out, AES_GCM_TAG_BYTES);
            zero_output(ecc_ephem_out, HYBRID_ECC_KEY_BYTES);
            zero_output(pqc_cipher_out, HYBRID_PQC_CIPHERTEXT_BYTES);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn hybrid_decrypt(
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    iv_ptr: *const u8,
    tag_ptr: *const u8,
    ecc_ephem_ptr: *const u8,
    pqc_cipher_ptr: *const u8,
    ecc_priv_ptr: *const u8,
    pqc_priv_ptr: *const u8,
    output_ptr: *mut u8,
    output_len: usize,
) -> i32 {
    if output_len < ciphertext_len {
        return -1;
    }
    if iv_ptr.is_null()
        || tag_ptr.is_null()
        || ecc_ephem_ptr.is_null()
        || pqc_cipher_ptr.is_null()
        || ecc_priv_ptr.is_null()
        || pqc_priv_ptr.is_null()
        || (ciphertext_len != 0 && ciphertext_ptr.is_null())
        || (output_len != 0 && output_ptr.is_null())
    {
        return -1;
    }
    let ciphertext = match input_slice(ciphertext_ptr, ciphertext_len) {
        Some(ciphertext) => ciphertext,
        None => return -1,
    };
    let iv = match fixed_input::<12>(iv_ptr) {
        Some(iv) => iv,
        None => return -1,
    };
    let tag = match fixed_input::<16>(tag_ptr) {
        Some(tag) => tag,
        None => return -1,
    };
    let ecc_ephemeral_pub = match fixed_input::<32>(ecc_ephem_ptr) {
        Some(ecc_ephemeral_pub) => ecc_ephemeral_pub,
        None => return -1,
    };
    let pqc_ciphertext = match fixed_input::<1088>(pqc_cipher_ptr) {
        Some(pqc_ciphertext) => pqc_ciphertext,
        None => return -1,
    };

    let _ecc_priv = match fixed_input::<32>(ecc_priv_ptr) {
        Some(ecc_priv) => ecc_priv,
        None => return -1,
    };
    let pqc_priv = match fixed_input::<2400>(pqc_priv_ptr) {
        Some(pqc_priv) => pqc_priv,
        None => return -1,
    };

    match hybrid_decrypt_payload(
        ciphertext,
        iv,
        tag,
        ecc_ephemeral_pub,
        pqc_ciphertext,
        _ecc_priv,
        pqc_priv,
    ) {
        Ok(plaintext) => {
            if ciphertext_len != 0 {
                core::ptr::copy_nonoverlapping(plaintext.as_ptr(), output_ptr, ciphertext_len);
            }
            0
        }
        Err(_) => {
            zero_output(output_ptr, output_len);
            -1
        }
    }
}
