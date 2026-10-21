#![cfg(feature = "aes-gcm")]
use hybrid_crypto::aes_gcm::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn decode_hex(s: &str) -> std::vec::Vec<u8> {
    if s.is_empty() {
        return std::vec::Vec::new();
    }
    let s = s.replace(" ", "");
    let mut out = std::vec::Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap());
    }
    out
}

#[test]
#[allow(clippy::manual_strip)]
#[allow(unused_assignments)]
fn test_aes_gcm_nist_kats() {
    let file = match File::open("gcmEncryptExtIV256.rsp") {
        Ok(f) => f,
        Err(_) => {
            println!("Skipping NIST AES-GCM KATs because gcmEncryptExtIV256.rsp is missing.");
            return;
        }
    };
    let reader = BufReader::new(file);

    let mut key = std::vec::Vec::new();
    let mut iv = std::vec::Vec::new();
    let mut pt = std::vec::Vec::new();
    let mut aad = std::vec::Vec::new();
    let mut ct = std::vec::Vec::new();
    let mut tag = std::vec::Vec::new();

    let mut count = 0;

    for line in reader.lines() {
        let line = line.unwrap();
        if line.starts_with("Key = ") {
            key = decode_hex(&line[6..]);
        } else if line.starts_with("IV = ") {
            iv = decode_hex(&line[5..]);
        } else if line.starts_with("PT = ") {
            pt = decode_hex(&line[5..]);
        } else if line.starts_with("AAD = ") {
            aad = decode_hex(&line[6..]);
        } else if line.starts_with("CT = ") {
            ct = decode_hex(&line[5..]);
        } else if line.starts_with("Tag = ") {
            tag = decode_hex(&line[6..]);

            // We have a full test case, let's run it!
            if iv.len() != 12 {
                continue; // We only support 96-bit IVs (12 bytes) right now.
            }
            if tag.len() != 16 {
                continue; // The library strictly enforces 128-bit tags.
            }

            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key);
            let mut iv_arr = [0u8; 12];
            iv_arr.copy_from_slice(&iv);

            // Test Encryption
            let mut computed_ct = std::vec![0u8; pt.len()];
            let computed_tag = aes256_gcm_encrypt(&key_arr, &iv_arr, &aad, &pt, &mut computed_ct);
            assert_eq!(
                computed_ct, ct,
                "NIST AES-GCM Encrypt CT failed at count {}",
                count
            );
            assert_eq!(
                computed_tag,
                tag.as_slice(),
                "NIST AES-GCM Encrypt Tag failed at count {}",
                count
            );

            // Test Decryption
            let mut computed_pt = std::vec![0u8; ct.len()];
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(&tag);
            aes256_gcm_decrypt(&key_arr, &iv_arr, &aad, &ct, &tag_arr, &mut computed_pt).unwrap();
            assert_eq!(
                computed_pt, pt,
                "NIST AES-GCM Decrypt failed at count {}",
                count
            );

            count += 1;
        }
    }

    assert!(count > 0, "No tests executed!");
    println!(
        "Successfully passed {} NIST AES-256-GCM test vectors!",
        count
    );
}

#[test]
fn test_aes_gcm_auth_failure() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    let pt = b"secret message";

    let mut ct = std::vec![0u8; pt.len()];
    let tag = aes256_gcm_encrypt(&key, &iv, &aad, pt, &mut ct);

    // Tamper with ciphertext
    ct[0] ^= 1;
    let mut dec = std::vec![0u8; pt.len()];
    let result = aes256_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut dec);
    assert!(
        result.is_err(),
        "Decryption must fail on tampered ciphertext"
    );

    // Ensure plaintext buffer was zeroed (defense in depth)
    assert_eq!(
        dec,
        std::vec![0u8; pt.len()],
        "Plaintext buffer was not zeroized on failure"
    );
}

#[test]
fn test_aes_gcm_decrypt_rejects_wrong_output_length() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    let pt = b"secret message";

    let mut ct = std::vec![0u8; pt.len()];
    let tag = aes256_gcm_encrypt(&key, &iv, &aad, pt, &mut ct);

    let mut short_dec = std::vec![0xA5u8; pt.len() - 1];
    let result = aes256_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut short_dec);

    assert!(
        result.is_err(),
        "Decryption must reject the wrong output length"
    );
    assert_eq!(
        short_dec,
        std::vec![0u8; pt.len() - 1],
        "Plaintext buffer was not zeroized after length rejection"
    );
}

#[test]
fn test_aes_gcm_aad_only() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = b"authenticated but not encrypted";
    let pt = [0u8; 0];

    let mut ct = std::vec![0u8; 0];
    let tag = aes256_gcm_encrypt(&key, &iv, aad, &pt, &mut ct);

    let mut dec = std::vec![0u8; 0];
    let result = aes256_gcm_decrypt(&key, &iv, aad, &ct, &tag, &mut dec);
    assert!(result.is_ok(), "AAD-only decryption failed");

    // Tamper with AAD
    let mut wrong_aad = std::vec![0u8; aad.len()];
    wrong_aad.copy_from_slice(aad);
    wrong_aad[0] ^= 1;
    let result2 = aes256_gcm_decrypt(&key, &iv, &wrong_aad, &ct, &tag, &mut dec);
    assert!(result2.is_err(), "Decryption must fail on tampered AAD");
}

#[test]
fn test_aes_gcm_large_plaintext() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    let pt = vec![0x42u8; 65536]; // 64 KB

    let mut ct = vec![0u8; pt.len()];
    let tag = aes256_gcm_encrypt(&key, &iv, &aad, &pt, &mut ct);

    let mut dec = vec![0u8; pt.len()];
    aes256_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut dec).unwrap();
    assert_eq!(pt, dec, "Large plaintext decryption failed");
}

#[test]
fn test_aes_gcm_invalid_tags_and_replay() {
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = [0u8; 0];
    let pt = b"secret message";

    let mut ct = vec![0u8; pt.len()];
    let mut tag = aes256_gcm_encrypt(&key, &iv, &aad, pt, &mut ct);

    // Invalid Tag
    tag[0] ^= 1;
    let mut dec = vec![0u8; pt.len()];
    assert!(aes256_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut dec).is_err(), "Tampered tag bypassed verification");
    
    // Replay Conditions (reusing IV for different message)
    // In GCM, reusing IV with same key compromises confidentiality and authenticity
    let pt2 = b"secret messagf"; // 1 bit diff
    let mut ct2 = vec![0u8; pt2.len()];
    let tag2 = aes256_gcm_encrypt(&key, &iv, &aad, pt2, &mut ct2);
    
    // We expect the XOR difference of ciphertexts to match the XOR difference of plaintexts
    let ct_xor = ct[13] ^ ct2[13];
    let pt_xor = pt[13] ^ pt2[13];
    assert_eq!(ct_xor, pt_xor, "IV reuse test failed: stream cipher property broken");
}
