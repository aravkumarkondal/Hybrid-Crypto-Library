use alloc::vec::Vec;
use alloc::string::String;
use hybrid_crypto::sha2::Sha256;
use crate::identity::IdentityPublicKey;
use core::fmt::Write;

pub struct SafetyNumber {
    pub fingerprint: [u8; 32],
}

impl SafetyNumber {
    #[must_use]
    pub fn generate(local_id: &IdentityPublicKey, remote_id: &IdentityPublicKey) -> Self {
        let mut bytes1 = Vec::new();
        bytes1.extend_from_slice(&local_id.ecc_public);
        bytes1.extend_from_slice(&local_id.pqc_public);
        
        let mut bytes2 = Vec::new();
        bytes2.extend_from_slice(&remote_id.ecc_public);
        bytes2.extend_from_slice(&remote_id.pqc_public);

        if bytes1 > bytes2 {
            core::mem::swap(&mut bytes1, &mut bytes2);
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes1);
        hasher.update(&bytes2);
        let fingerprint = hasher.finalize();

        Self { fingerprint }
    }

    #[must_use]
    pub fn display_numeric(&self) -> String {
        let mut s = String::with_capacity(65);
        for i in 0..6 {
            let offset = i * 5;
            let mut val = 0u64;
            for j in 0..5 {
                val = (val << 8) | u64::from(self.fingerprint[offset + j]);
            }
            // Modulo 10^10 guarantees it fits in 10 digits
            let chunk = val % 10_000_000_000;
            write!(&mut s, "{chunk:010} ").unwrap();
        }
        s.pop(); // remove trailing space
        s
    }

    #[must_use]
    pub const fn display_qr_code(&self) -> [u8; 32] {
        self.fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn test_safety_number_determinism() {
        use crate::ffi::block_on;
        let id1 = block_on(IdentityKeyPair::generate(&[1; 32], &[2; 32]).public_key());
        let id2 = block_on(IdentityKeyPair::generate(&[3; 32], &[4; 32]).public_key());

        let sn1 = SafetyNumber::generate(&id1, &id2);
        let sn2 = SafetyNumber::generate(&id2, &id1);

        assert_eq!(sn1.fingerprint, sn2.fingerprint);
        assert_eq!(sn1.display_numeric(), sn2.display_numeric());
        
        // Output format check
        let numeric = sn1.display_numeric();
        assert_eq!(numeric.len(), 65); // 6 chunks * 10 digits + 5 spaces
        assert!(numeric.chars().all(|c| c.is_digit(10) || c == ' '));
    }
    
    #[test]
    fn test_safety_number_distinctness() {
        use crate::ffi::block_on;
        let id1 = block_on(IdentityKeyPair::generate(&[1; 32], &[2; 32]).public_key());
        let id2 = block_on(IdentityKeyPair::generate(&[3; 32], &[4; 32]).public_key());
        let id3 = block_on(IdentityKeyPair::generate(&[5; 32], &[6; 32]).public_key());

        let sn1 = SafetyNumber::generate(&id1, &id2);
        let sn2 = SafetyNumber::generate(&id1, &id3);

        assert_ne!(sn1.fingerprint, sn2.fingerprint);
        assert_ne!(sn1.display_numeric(), sn2.display_numeric());
    }
}
