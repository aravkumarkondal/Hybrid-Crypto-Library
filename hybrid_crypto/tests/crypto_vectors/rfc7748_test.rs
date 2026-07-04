#![cfg(feature = "x25519")]
use hybrid_crypto::x25519;

fn decode_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let s = s.replace(" ", "");
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn test_x25519_rfc7748_base() {
    let scalar = decode_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let point = decode_hex("0900000000000000000000000000000000000000000000000000000000000000");
    let expected = decode_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    let result = x25519::x25519(&scalar, &point).unwrap();
    assert_eq!(result, expected, "RFC 7748 Alice multiplication failed");
    
    let bob_scalar = decode_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_expected = decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let bob_result = x25519::x25519(&bob_scalar, &point).unwrap();
    assert_eq!(bob_result, bob_expected, "RFC 7748 Bob multiplication failed");
    
    let shared_expected = decode_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let alice_shared = x25519::x25519(&scalar, &bob_expected).unwrap();
    let bob_shared = x25519::x25519(&bob_scalar, &expected).unwrap();
    assert_eq!(alice_shared, shared_expected, "RFC 7748 Alice Shared failed");
    assert_eq!(bob_shared, shared_expected, "RFC 7748 Bob Shared failed");
}

#[test]
fn test_x25519_rfc7748_iterated() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = [0u8; 32];
    u[0] = 9;

    let expected_1 = decode_hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    let expected_1000 = decode_hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    let _expected_1000000 = decode_hex("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
    
    let mut result = [0u8; 32];
    for i in 0..1000 {
        result = x25519::x25519(&k, &u).unwrap();
        u = k;
        k = result;
        if i == 0 {
            assert_eq!(result, expected_1, "RFC 7748 Iteration 1 failed");
        }
    }
    
    assert_eq!(result, expected_1000, "RFC 7748 Iteration 1000 failed");
}

#[test]
fn test_x25519_low_order_points() {
    let scalar = decode_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    
    // 0
    let p0 = [0u8; 32];
    let r0 = x25519::x25519(&scalar, &p0);
    assert!(r0.is_err() || r0.unwrap() == [0u8; 32], "Low order point 0 not rejected/zeroed");

    // 1
    let mut p1 = [0u8; 32]; p1[0] = 1;
    let r1 = x25519::x25519(&scalar, &p1);
    assert!(r1.is_err() || r1.unwrap() == [0u8; 32], "Low order point 1 not rejected/zeroed");
}

#[test]
fn test_x25519_reflection_and_shared_secret() {
    let scalar1 = decode_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let scalar2 = decode_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let base = decode_hex("0900000000000000000000000000000000000000000000000000000000000000");

    let pk1 = x25519::x25519(&scalar1, &base).unwrap();
    let pk2 = x25519::x25519(&scalar2, &base).unwrap();

    let ss1 = x25519::x25519(&scalar1, &pk2).unwrap();
    let ss2 = x25519::x25519(&scalar2, &pk1).unwrap();

    assert_eq!(ss1, ss2, "Shared secret consistency failed");
    
    // Reflection
    let refl1 = x25519::x25519(&scalar1, &pk1).unwrap();
    let refl2 = x25519::x25519(&scalar2, &pk2).unwrap();
    assert_ne!(ss1, refl1, "Reflection attack shared secret matched");
    assert_ne!(ss2, refl2, "Reflection attack shared secret matched");
}
