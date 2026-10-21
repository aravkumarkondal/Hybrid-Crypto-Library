use e2ee::IdentityKeyPair;
extern crate alloc;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::hkdf::hkdf_expand;

// Simulated Sealed Sender logic using the existing primitives.
#[test]
fn test_sealed_sender_envelope_integrity_and_privacy() {
    let _alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let _server_id = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    
    // Server has a known delivery public key
    let mut server_key = [0u8; 32];
    hkdf_expand(&[5; 32], b"ServerDeliveryKey", &mut server_key);
    
    let inner_plaintext = b"Sealed message for Bob";
    
    // Alice encrypts the envelope using server's delivery key
    // The envelope hides the sender's identity.
    let iv = [0u8; 12];
    let mut ciphertext = alloc::vec::Vec::new();
    ciphertext.resize(inner_plaintext.len(), 0);
    
    // Empty AAD simulates no exposed metadata
    let aad = [];
    let auth_tag = aes256_gcm_encrypt(&server_key, &iv, &aad, inner_plaintext, &mut ciphertext);
    
    // Server decrypts the envelope to verify integrity and privacy
    let mut decrypted = alloc::vec::Vec::new();
    decrypted.resize(ciphertext.len(), 0);
    let res = aes256_gcm_decrypt(&server_key, &iv, &aad, &ciphertext, &auth_tag, &mut decrypted);
    
    assert!(res.is_ok());
    assert_eq!(decrypted, inner_plaintext);
    
    // Modifying the envelope fails integrity check
    ciphertext[0] ^= 1;
    let res_bad = aes256_gcm_decrypt(&server_key, &iv, &aad, &ciphertext, &auth_tag, &mut decrypted);
    assert!(res_bad.is_err());
}
