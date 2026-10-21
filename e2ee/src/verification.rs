use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use crate::identity::IdentityPublicKey;
use hybrid_crypto::sha2::Sha256;

/// A Fingerprint combines an Account Identity and all active Device Identities 
/// to form a single verifiable identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash: [u8; 32],
}

impl Fingerprint {
    /// Computes a hybrid fingerprint from the Account and its devices.
    #[must_use]
    pub fn compute(account_pub: &IdentityPublicKey, device_pubs: &[IdentityPublicKey]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"FINGERPRINT_V1");
        
        hasher.update(&account_pub.ecc_public);
        hasher.update(&account_pub.pqc_public);
        
        // Sort device public keys to ensure deterministic fingerprint regardless of list order
        let mut dev_keys = Vec::new();
        for d in device_pubs {
            let mut blob = Vec::new();
            blob.extend_from_slice(&d.ecc_public);
            blob.extend_from_slice(&d.pqc_public);
            dev_keys.push(blob);
        }
        dev_keys.sort();
        
        for k in dev_keys {
            hasher.update(&k);
        }
        
        Self {
            hash: hasher.finalize(),
        }
    }

    /// Returns a numeric, human-readable formatting of the fingerprint.
    /// This converts the hash into a sequence of digits grouped by 5 for display.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        let mut result = String::new();
        
        for i in 0..6 {
            // Take 5 bytes per block to generate a 10-digit decimal string
            let mut chunk = [0u8; 8];
            let start = i * 5;
            chunk[3..8].copy_from_slice(&self.hash[start..start + 5]);
            let val = u64::from_be_bytes(chunk);
            let formatted = format!("{:010}", val % 10_000_000_000);
            
            result.push_str(&formatted[0..5]);
            result.push(' ');
            result.push_str(&formatted[5..10]);
            
            if i < 5 {
                result.push(' ');
            }
        }
        
        result
    }
}
