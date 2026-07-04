use e2ee::{IdentityKeyPair, SafetyNumber};

#[test]
fn test_safety_numbers_deterministic_generation() {
    let alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let bob = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    
    let sn1 = SafetyNumber::generate(&alice.public_key(), &bob.public_key());
    let sn2 = SafetyNumber::generate(&alice.public_key(), &bob.public_key());
    
    // Deterministic generation
    assert_eq!(sn1.fingerprint, sn2.fingerprint);
    
    // Order should not matter (commutative in some implementations, but let's just check consistency)
    let sn3 = SafetyNumber::generate(&bob.public_key(), &alice.public_key());
    assert_eq!(sn1.fingerprint, sn3.fingerprint);
}

#[test]
fn test_safety_numbers_identity_substitution_protection() {
    let alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let bob = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let eve = IdentityKeyPair::generate(&[5; 32], &[6; 32]);
    
    let sn_legit = SafetyNumber::generate(&alice.public_key(), &bob.public_key());
    let sn_eve = SafetyNumber::generate(&alice.public_key(), &eve.public_key());
    
    assert_ne!(sn_legit.fingerprint, sn_eve.fingerprint);
    
    // Bob's key changes slightly (e.g. key compromise)
    let bob_new = IdentityKeyPair::generate(&[33; 32], &[44; 32]);
    let sn_new = SafetyNumber::generate(&alice.public_key(), &bob_new.public_key());
    
    assert_ne!(sn_legit.fingerprint, sn_new.fingerprint);
}
