use e2ee::credentials::CredentialIssuer;
use e2ee::identity::IdentityKeyPair;

#[test]
fn test_credential_issuance_and_verification() {
    let authority_keypair = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let authority_public = futures::executor::block_on(authority_keypair.public_key());
    
    let issuer = CredentialIssuer::new(authority_keypair);
    
    let attributes = b"Role: Employee";
    let seed_ecc = &[3; 32];
    let seed_pqc = &[4; 32];
    let sig_entropy = &[5; 32];
    
    let credential = futures::executor::block_on(issuer.issue_credential(attributes, seed_ecc, seed_pqc, sig_entropy))
        .expect("Failed to issue credential");
        
    let public_cred = futures::executor::block_on(credential.to_public());
    
    // VERIFIED: Signature verification passes
    assert!(public_cred.verify(&authority_public).is_ok());
}

#[test]
fn test_credential_unlinkability() {
    let authority_keypair = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let issuer = CredentialIssuer::new(authority_keypair);
    
    // User gets two credentials with different seeds
    let attributes = b"Role: AnonymousUser";
    
    let cred1 = futures::executor::block_on(issuer.issue_credential(attributes, &[10; 32], &[11; 32], &[12; 32])).unwrap();
    let cred2 = futures::executor::block_on(issuer.issue_credential(attributes, &[20; 32], &[21; 32], &[22; 32])).unwrap();
    
    // HIGH CONFIDENCE: The two public keys must be entirely different, rendering them unlinkable
    let pub1 = futures::executor::block_on(cred1.keypair.public_key());
    let pub2 = futures::executor::block_on(cred2.keypair.public_key());
    assert_ne!(pub1.ecc_public, pub2.ecc_public);
    assert_ne!(pub1.pqc_public, pub2.pqc_public);
}
