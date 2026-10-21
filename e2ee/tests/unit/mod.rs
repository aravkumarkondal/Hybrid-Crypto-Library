#![allow(unsafe_code)]
use e2ee::ffi::*;

#[test]
fn test_e2ee_ffi_bindings() {
    let ent_alice_ecc = [0x01; 32];
    let ent_alice_pqc = [0x02; 32];
    let mut alice_ecc_priv = [0u8; 32];
    let mut alice_ecc_pub = [0u8; 32];
    let mut alice_pqc_priv = vec![0u8; E2EE_MLDSA87_PRIVATE_BYTES];
    let mut alice_pqc_pub = vec![0u8; E2EE_MLDSA87_PUBLIC_BYTES];
    let mut alice_pqc_pub_len = 0;
    
    unsafe {
        assert_eq!(e2ee_identity_generate(
            ent_alice_ecc.as_ptr(),
            ent_alice_pqc.as_ptr(),
            alice_ecc_priv.as_mut_ptr(),
            alice_ecc_pub.as_mut_ptr(),
            alice_pqc_priv.as_mut_ptr(),
            alice_pqc_pub.as_mut_ptr(),
            &mut alice_pqc_pub_len,
        ), 0);
    }
}
