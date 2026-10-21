use alloc::vec::Vec;
use crate::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use crate::utils::SecretKey;

pub struct SignatureKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: SecretKey,
}

pub fn generate_keypair(seed: &[u8; 32]) -> SignatureKeyPair {
    let (pk, sk) = ml_dsa_87_keypair(seed);
    SignatureKeyPair {
        public_key: pk,
        private_key: sk,
    }
}

pub fn sign(message: &[u8], private_key: &SecretKey, rnd: &[u8; 32]) -> Result<Vec<u8>, crate::CryptoError> {
    ml_dsa_87_sign(private_key, message, &[], rnd)
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // We only support ML-DSA-87 in this wrapper
    if public_key.len() != 2592 {
        return false;
    }
    ml_dsa_87_verify(public_key, message, &[], signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_87_signature_cycle() {
        let seed = [0x5A; 32];
        let keypair = generate_keypair(&seed);
        
        let message = b"Hello, post-quantum ML-DSA-87 world! This is a test of zero-dependency FIPS 204.";
        
        let rnd = [0x99; 32];
        let sig = sign(message, &keypair.private_key, &rnd).unwrap();
        assert!(sig.len() > 1000); // Should be quite large
        
        let is_valid = verify(message, &sig, &keypair.public_key);
        assert!(is_valid, "ML-DSA-87 Signature verification failed!");
        
        // Test tampering
        let mut tampered_message = message.to_vec();
        tampered_message[0] ^= 1;
        let is_valid_tampered = verify(&tampered_message, &sig, &keypair.public_key);
        assert!(!is_valid_tampered, "Tampered message should fail verification!");
        
        let mut tampered_sig = sig.clone();
        tampered_sig[100] ^= 1;
        let is_valid_sig_tampered = verify(message, &tampered_sig, &keypair.public_key);
        assert!(!is_valid_sig_tampered, "Tampered signature should fail verification!");
    }

    #[test]
    fn test_ml_dsa_87_red_team_context_length() {
        let seed = [0x5A; 32];
        let keypair = generate_keypair(&seed);
        let message = b"Test message";
        let rnd = [0x99; 32];
        
        let valid_ctx = [0u8; 255];
        let result = crate::ml_dsa::ml_dsa_87_sign(&keypair.private_key, message, &valid_ctx, &rnd);
        assert!(result.is_ok(), "Context of length 255 should be accepted");
        
        let invalid_ctx = [0u8; 256];
        let result2 = crate::ml_dsa::ml_dsa_87_sign(&keypair.private_key, message, &invalid_ctx, &rnd);
        assert!(result2.is_err(), "Context of length 256 MUST be rejected");
    }

    #[test]
    fn test_ml_dsa_87_red_team_hint_malleability() {
        let seed = [0x5A; 32];
        let keypair = generate_keypair(&seed);
        let message = b"Malleability test";
        let rnd = [0x99; 32];
        
        let sig = crate::ml_dsa::ml_dsa_87_sign(&keypair.private_key, message, &[], &rnd).unwrap();
        assert!(verify(message, &sig, &keypair.public_key), "Original sig must be valid");
        
        // Find where the hint array starts.
        // sig len = 4627. Hint array starts at 4627 - (75 + 8) = 4544
        let hint_start = 4544;
        let _omega_plus_k = 83; // OMEGA=75, K=8
        
        // Let's modify the unused padding bytes of the hint array.
        // The weight of the hint should be < 75. 
        // The weight is stored at h_enc[OMEGA + i] which is h_enc[75 + i]... wait, the structure is:
        // h_enc has OMEGA bytes for indices, and K bytes for offsets.
        // The actual length of used bytes in the OMEGA array is given by h_enc[OMEGA + K - 1].
        let final_offset = sig[hint_start + 75 + 7] as usize;
        
        if final_offset < 75 {
            // Tamper with the padding byte
            let mut tampered_padding_sig = sig.clone();
            tampered_padding_sig[hint_start + final_offset] = 1; // Change from 0 to 1
            assert!(!verify(message, &tampered_padding_sig, &keypair.public_key), "Non-zero padding bytes in hint MUST be rejected");
        }
        
        // Tamper with ordering: if there are at least two hints, swap them to make them unordered
        if final_offset > 1 {
            let mut tampered_order_sig = sig.clone();
            tampered_order_sig.swap(hint_start, hint_start + 1);
            
            // Note: if they were the same, it's not strictly increasing anyway, but FIPS 204 requires strictly increasing.
            assert!(!verify(message, &tampered_order_sig, &keypair.public_key), "Unordered hint indices MUST be rejected");
        }
    }
}
