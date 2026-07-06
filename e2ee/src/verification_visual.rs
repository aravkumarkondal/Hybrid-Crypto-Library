use alloc::vec::Vec;
use alloc::string::String;
use hybrid_crypto::hkdf::hkdf_expand;
use hybrid_crypto::sha2::Sha256;
use crate::identity::IdentityPublicKey;

mod pgp_words {
    // This will be included from pgp_words.rs
    include!("pgp_words.rs");
}

/// A structured container for visual verification payloads.
/// 
/// Combines identities and keys to generate a domain-separated, deterministic
/// digest that can be displayed as numeric blocks, PGP-style word lists, or 
/// passed to geometric identicon generators.
pub struct HybridFingerprint {
    digest: [u8; 32],
}

impl HybridFingerprint {
    /// Generates a hybrid fingerprint for out-of-band verification.
    ///
    /// The fingerprint binds the user's account identity, their device identity, 
    /// and their active ephemeral/prekeys (X25519 and ML-DSA) for an E2EE session.
    #[must_use]
    pub fn generate(
        account_identity: &IdentityPublicKey,
        device_identity: &IdentityPublicKey,
        x25519_key: &[u8; 32],
        pqc_key: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        
        // Domain separation
        hasher.update(b"HYBRID_VERIFICATION_V1");
        
        hasher.update(&account_identity.ecc_public);
        hasher.update(&account_identity.pqc_public);
        
        hasher.update(&device_identity.ecc_public);
        hasher.update(&device_identity.pqc_public);
        
        hasher.update(x25519_key);
        hasher.update(pqc_key);
        
        let initial_hash = hasher.finalize();
        
        // Expand the hash to ensure uniformly distributed 32 bytes for the SAS
        let mut final_digest = [0u8; 32];
        hkdf_expand(&initial_hash, b"VISUAL_SAS_EXPANSION", &mut final_digest);
        
        Self {
            digest: final_digest,
        }
    }

    /// Returns the raw 32-byte digest of the fingerprint
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Generates a numeric SAS (Short Authentication String).
    /// 
    /// Formats the digest as blocks of 5 decimal digits.
    /// Typically, users only compare the first 4 blocks (20 digits).
    /// Returns 8 blocks (40 digits) covering the full 32-byte entropy space (actually 32 bytes = 256 bits, we use 4 bytes per block).
    #[must_use]
    pub fn numeric_sas(&self) -> String {
        let mut blocks = Vec::new();
        
        for chunk in self.digest.chunks_exact(4) {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            let val = u32::from_be_bytes(b);
            // Modulo 100,000 to get 5 digits
            let block_val = val % 100000;
            // Use standard format macro for padding (no_std alloc::format! is available)
            blocks.push(alloc::format!("{block_val:05}"));
        }
        
        blocks.join(" ")
    }

    /// Generates a PGP-style human-readable word list.
    /// 
    /// Uses the standard PGP word list (even/odd) mapping bytes to words.
    #[must_use]
    pub fn pgp_word_list(&self) -> String {
        let mut words = Vec::new();
        
        for (i, &byte) in self.digest.iter().enumerate() {
            let word = if i % 2 == 0 {
                pgp_words::PGP_EVEN_WORDS[byte as usize]
            } else {
                pgp_words::PGP_ODD_WORDS[byte as usize]
            };
            words.push(word);
        }
        
        words.join("-")
    }
}
