extern crate alloc;
use e2ee::KeyTransparencyLog;

#[test]
fn test_transparency_log_inclusion_proof() {
    let mut log = KeyTransparencyLog::new();
    
    // Add 5 device keys to the log
    log.append(b"Device1_PubKey");
    log.append(b"Device2_PubKey");
    log.append(b"Device3_PubKey");
    log.append(b"Device4_PubKey");
    log.append(b"Device5_PubKey");
    
    let expected_root = log.root();

    // Verify inclusion of Device 3 (index 2)
    let proof = log.prove_inclusion(2);
    
    let is_valid = KeyTransparencyLog::verify_inclusion(
        b"Device3_PubKey",
        2,
        5,
        &proof,
        &expected_root,
    );
    assert!(is_valid, "Inclusion proof must verify for an honest server.");

    // Malicious Server Simulation: Split-View Attack
    // The server tries to serve an omitted or modified key for Device 3
    let is_valid_malicious = KeyTransparencyLog::verify_inclusion(
        b"Device3_Malicious_PubKey",
        2,
        5,
        &proof,
        &expected_root,
    );
    assert!(!is_valid_malicious, "Inclusion proof must FAIL for maliciously modified key payloads.");
}
