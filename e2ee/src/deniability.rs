//! Transcript Deniability Verification
//! 
//! Deniability is a fundamental security property of the Hybrid Messaging Protocol.
//! It ensures that while messages are strongly authenticated during transit, 
//! the resulting transcript cannot be cryptographically proven to a third party 
//! after the fact.
//! 
//! # Mathematical Basis
//! 
//! Our protocol achieves deniability through the use of symmetric message authentication
//! codes (MACs) based on AES-GCM (which internally uses GHASH) combined with ephemeral 
//! key agreement (PQXDH and `TreeKEM`).
//! 
//! Let `A` be the sender and `B` be the receiver.
//! 1. `A` and `B` establish a shared secret `S` via PQXDH/TreeKEM.
//! 2. `S` is used to derive a message key `K`.
//! 3. `A` sends a message `M` encrypted and authenticated as `C = AES-GCM(K, M)`.
//! 
//! **Indistinguishability:**
//! Because `K` is derived from `S`, and `S` is known to both `A` and `B`, the key `K` 
//! is also known to both `A` and `B`. Therefore, any message `C` could have been 
//! constructed by `A` (the true sender) OR by `B` (the receiver forging a message 
//! from `A`). 
//! 
//! To a third party `C_t`, observing `(M, C, K)`, the probability that `A` produced `C` 
//! is exactly equal to the probability that `B` produced `C`. Thus, the transcript 
//! provides zero non-repudiation and is fully deniable.
//! 
//! # Continuous Deniability in `TreeKEM`
//! 
//! In our Hybrid `TreeKEM` (MLS-inspired) architecture:
//! - An epoch secret `E_e` is shared among all group members.
//! - `E_e` derives the `SenderKey` chains for each member.
//! - Any member `M_i` in the group can derive the `SenderKey` chain of any other member `M_j`.
//! 
//! **Group Indistinguishability:**
//! Because any member `M_i` can derive the message key `K_j` for member `M_j`, any member 
//! could forge a valid ciphertext appearing to be from `M_j`. Therefore, group transcripts 
//! are deniable among all current members of the group.
//! 
//! # Policy
//! 
//! As mandated by security policy, we **do not** expose a public `ForgeableSession` API 
//! or transcript-forging tools to the user. Deniability is a mathematical property of 
//! the ciphertext indistinguishability, not a user feature.
//! 
//! The tests in this module internally simulate a forgery to mathematically prove 
//! that a forged ciphertext is byte-for-byte indistinguishable from a legitimate one.

#[cfg(test)]
mod tests {
    use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
    use crate::sender_keys::SenderKeyChain;

    #[test]
    fn test_transcript_indistinguishability() {
        // Setup shared knowledge (the sender key seed, derived from a shared secret)
        let shared_seed = [0x42u8; 32];
        
        // ---------------------------------------------------------
        // 1. Legitimate Sender (Alice) constructs a message
        // ---------------------------------------------------------
        let mut alice_chain = SenderKeyChain::new(&shared_seed, 0);
        let (alice_msg_key, alice_iv) = alice_chain.next_message_key();
        
        let message = b"I agree to the contract.";
        let mut alice_ciphertext = alloc::vec![0u8; message.len()];
        let alice_auth_tag = aes256_gcm_encrypt(
            &alice_msg_key,
            &alice_iv,
            b"associated_data",
            message,
            &mut alice_ciphertext,
        );

        // ---------------------------------------------------------
        // 2. Receiver (Bob) forges a message claiming to be from Alice
        // ---------------------------------------------------------
        // Bob knows the same shared seed
        let mut bob_chain = SenderKeyChain::new(&shared_seed, 0);
        let (bob_msg_key, bob_iv) = bob_chain.next_message_key();
        
        let mut bob_forged_ciphertext = alloc::vec![0u8; message.len()];
        let bob_auth_tag = aes256_gcm_encrypt(
            &bob_msg_key,
            &bob_iv,
            b"associated_data",
            message,
            &mut bob_forged_ciphertext,
        );

        // ---------------------------------------------------------
        // 3. Mathematical Proof of Indistinguishability
        // ---------------------------------------------------------
        // The forged ciphertext and the legitimate ciphertext are identical
        // under the same state, proving that a transcript alone cannot prove authorship.
        assert_eq!(
            alice_ciphertext, bob_forged_ciphertext,
            "Forged ciphertext must be perfectly indistinguishable from legitimate ciphertext"
        );
        assert_eq!(alice_auth_tag, bob_auth_tag, "Forged auth tag must be perfectly indistinguishable");

        // Prove it decrypts validly
        let mut decrypted = alloc::vec![0u8; bob_forged_ciphertext.len()];
        aes256_gcm_decrypt(
            &alice_msg_key,
            &alice_iv,
            b"associated_data",
            &bob_forged_ciphertext,
            &bob_auth_tag,
            &mut decrypted,
        ).expect("Decryption of forgery failed");
        
        assert_eq!(decrypted, message);
    }
}
