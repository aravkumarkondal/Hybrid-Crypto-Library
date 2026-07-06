use hybrid_crypto::hkdf::{hkdf_extract, hkdf_expand};
use hkdf::Hkdf;
use sha2::Sha256;

#[test]
fn test_hkdf_differential() {
    let ikm = b"secret_key_material";
    let salt = b"salt_for_hkdf";
    let info = b"application_specific_info";

    // Standard rust-crypto HKDF
    let (prk, hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut expected_okm = [0u8; 42];
    hk.expand(info, &mut expected_okm).expect("HKDF expand failed");

    // Our internal Hybrid Crypto HKDF
    let our_prk = hkdf_extract(salt, ikm);
    assert_eq!(our_prk, prk.as_slice(), "Extract PRK mismatch");

    let mut our_okm = [0u8; 42];
    hkdf_expand(&our_prk, info, &mut our_okm);

    assert_eq!(our_okm, expected_okm, "Expand OKM mismatch");
}

#[test]
fn test_hkdf_differential_empty_salt() {
    let ikm = b"secret_key_material";
    let info = b"application_specific_info";

    // Standard rust-crypto HKDF with empty salt
    let (prk, hk) = Hkdf::<Sha256>::extract(None, ikm);
    let mut expected_okm = [0u8; 64];
    hk.expand(info, &mut expected_okm).expect("HKDF expand failed");

    // Our internal Hybrid Crypto HKDF with empty salt
    let our_prk = hkdf_extract(&[], ikm);
    assert_eq!(our_prk, prk.as_slice(), "Extract PRK mismatch");

    let mut our_okm = [0u8; 64];
    hkdf_expand(&our_prk, info, &mut our_okm);

    assert_eq!(our_okm, expected_okm, "Expand OKM mismatch");
}
