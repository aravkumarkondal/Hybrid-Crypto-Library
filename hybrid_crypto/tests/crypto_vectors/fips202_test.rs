#![cfg(feature = "sha3")]
use hybrid_crypto::keccak;

fn decode_hex(s: &str) -> std::vec::Vec<u8> {
    let s = s.replace(" ", "").replace("\n", "");
    let mut out = std::vec::Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap());
    }
    out
}

#[test]
fn test_sha3_256_kat() {
    let expected = decode_hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    let mut out = [0u8; 32];
    
    let mut state = keccak::KeccakState::new(136, 0x06); // SHA3-256 uses rate 136 and domain 0x06
    state.absorb(b"");
    state.finalize();
    state.squeeze(&mut out);

    assert_eq!(out.as_slice(), expected.as_slice(), "FIPS 202 SHA3-256 Empty String KAT failed");
}

#[test]
fn test_shake_256_kat() {
    let expected = decode_hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    let mut out = [0u8; 32];
    
    let mut state = keccak::KeccakState::new(136, 0x1f); // SHAKE-256 uses rate 136 and domain 0x1f
    state.absorb(b"");
    state.finalize();
    state.squeeze(&mut out);

    assert_eq!(out.as_slice(), expected.as_slice(), "FIPS 202 SHAKE-256 Empty String KAT failed");
}

#[test]
fn test_sha3_512_kat() {
    let expected = decode_hex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    let mut out = [0u8; 64];
    let mut state = keccak::KeccakState::new(72, 0x06); // SHA3-512 uses rate 72
    state.absorb(b"");
    state.finalize();
    state.squeeze(&mut out);
    assert_eq!(out.as_slice(), expected.as_slice(), "FIPS 202 SHA3-512 Empty String KAT failed");
}

#[test]
fn test_shake_128_kat() {
    let expected = decode_hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    let mut out = [0u8; 32];
    let mut state = keccak::KeccakState::new(168, 0x1f); // SHAKE-128 uses rate 168
    state.absorb(b"");
    state.finalize();
    state.squeeze(&mut out);
    assert_eq!(out.as_slice(), expected.as_slice(), "FIPS 202 SHAKE-128 Empty String KAT failed");
}

#[test]
fn test_sha3_256_streaming_and_long_input() {
    let mut state1 = keccak::KeccakState::new(136, 0x06);
    let mut state2 = keccak::KeccakState::new(136, 0x06);
    
    // Large input (2000 bytes)
    let mut input = vec![0u8; 2000];
    for i in 0..2000 {
        input[i] = (i % 256) as u8;
    }
    
    // One shot absorb
    state1.absorb(&input);
    state1.finalize();
    let mut out1 = [0u8; 32];
    state1.squeeze(&mut out1);
    
    // Streaming absorb
    for chunk in input.chunks(13) {
        state2.absorb(chunk);
    }
    state2.finalize();
    let mut out2 = [0u8; 32];
    state2.squeeze(&mut out2);
    
    assert_eq!(out1, out2, "Streaming absorb gave different result than one-shot absorb");
    assert_ne!(out1, [0u8; 32], "Output is all zeros");
}
