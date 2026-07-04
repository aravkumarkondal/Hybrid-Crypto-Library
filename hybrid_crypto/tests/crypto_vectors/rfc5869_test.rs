#![cfg(feature = "hkdf")]
use hybrid_crypto::hkdf;

fn decode_hex(s: &str) -> std::vec::Vec<u8> {
    let s = s.replace(" ", "").replace("\n", "");
    let mut out = std::vec::Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap());
    }
    out
}

#[test]
fn test_hkdf_rfc5869_tc1() {
    let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = decode_hex("000102030405060708090a0b0c");
    let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    let expected_prk = decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm = decode_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let prk = hkdf::hkdf_extract(&salt, &ikm);
    assert_eq!(prk.as_slice(), expected_prk.as_slice(), "RFC 5869 Extract TC1 failed");

    let mut okm = std::vec![0u8; 42];
    hkdf::hkdf_expand(&prk, &info, &mut okm);
    assert_eq!(okm, expected_okm, "RFC 5869 Expand TC1 failed");
}

#[test]
fn test_hkdf_rfc5869_empty_salt() {
    let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = decode_hex("");
    let info = decode_hex("");
    let prk = hkdf::hkdf_extract(&salt, &ikm);
    assert_eq!(prk.len(), 32);
    
    let mut okm = std::vec![0u8; 42];
    hkdf::hkdf_expand(&prk, &info, &mut okm);
    assert_eq!(okm.len(), 42);
}

#[test]
fn test_hkdf_empty_and_long_inputs() {
    let empty = &[];
    let prk_empty = hkdf::hkdf_extract(empty, empty);
    let mut okm_empty = [0u8; 32];
    hkdf::hkdf_expand(&prk_empty, empty, &mut okm_empty);
    assert_ne!(okm_empty, [0u8; 32], "HKDF with empty inputs failed to produce pseudo-random output");
    
    let long_salt = vec![1u8; 1024];
    let long_ikm = vec![2u8; 1024];
    let long_info = vec![3u8; 1024];
    let prk_long = hkdf::hkdf_extract(&long_salt, &long_ikm);
    let mut okm_long = [0u8; 8000]; // near the max 255 * hash_len (8160 for SHA3-256)
    hkdf::hkdf_expand(&prk_long, &long_info, &mut okm_long);
    assert_ne!(&okm_long[7900..8000], &[0u8; 100], "HKDF long output failed to populate");
}

#[test]
fn test_hkdf_domain_separation() {
    let ikm = b"secret";
    let salt = b"salt";
    let prk = hkdf::hkdf_extract(salt, ikm);
    
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    hkdf::hkdf_expand(&prk, b"domain1", &mut out1);
    hkdf::hkdf_expand(&prk, b"domain2", &mut out2);
    
    assert_ne!(out1, out2, "HKDF failed domain separation (different info gave same output)");
}
