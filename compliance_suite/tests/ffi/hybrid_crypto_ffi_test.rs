#![cfg(feature = "hybrid")]
use hybrid_crypto::ffi::{mldsa87_sign, mldsa87_verify};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign};

#[test]
fn test_mldsa87_sign_rejects_null_nonempty_context() {
    let seed = [0x42u8; 32];
    let (_pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"ffi context binding";
    let rnd = [0xA5u8; 32];
    let mut sig = [0x5Au8; 4627];

    let result = unsafe {
        mldsa87_sign(
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            1,
            rnd.as_ptr(),
            sk.as_ptr(),
            sig.as_mut_ptr(),
            sig.len(),
        )
    };

    assert_eq!(result, -1);
    assert_eq!(sig, [0u8; 4627]);
}

#[test]
fn test_mldsa87_verify_rejects_null_nonempty_context() {
    let seed = [0x24u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"ffi verify context binding";
    let rnd = [0x11u8; 32];
    let sig = ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap();

    let result = unsafe {
        mldsa87_verify(
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            1,
            sig.as_ptr(),
            pk.as_ptr(),
        )
    };

    assert_eq!(result, 0);
}

#[test]
fn test_mldsa87_ffi_accepts_null_empty_message_and_context() {
    let seed = [0x7Bu8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let rnd = [0x33u8; 32];
    let mut sig = [0u8; 4627];

    let sign_result = unsafe {
        mldsa87_sign(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            rnd.as_ptr(),
            sk.as_ptr(),
            sig.as_mut_ptr(),
            sig.len(),
        )
    };
    assert_eq!(sign_result, 0);

    let verify_result = unsafe {
        mldsa87_verify(
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            sig.as_ptr(),
            pk.as_ptr(),
        )
    };
    assert_eq!(verify_result, 1);
}
