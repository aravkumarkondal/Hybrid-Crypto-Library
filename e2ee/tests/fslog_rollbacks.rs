extern crate alloc;

use e2ee::fslog::FsLogStore;
use e2ee::errors::E2EError;

#[test]
fn test_fslog_integrity_and_tampering() {
    let genesis_key = [7u8; 32];
    let genesis_hash = [8u8; 32];
    
    let mut store = FsLogStore::new(&genesis_key, &genesis_hash);
    
    store.append(b"User Alice Registered", 1000).unwrap();
    store.append(b"User Alice Added Device", 1005).unwrap();
    store.append(b"Group Key Rotated", 1010).unwrap();
    
    // Normal Verification
    let decoded = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &store.entries).unwrap();
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[0].payload, b"User Alice Registered");
    assert_eq!(decoded[2].payload, b"Group Key Rotated");
    assert_eq!(decoded[0].sequence_num, 0);
    assert_eq!(decoded[2].sequence_num, 2);

    // Attack 1: Log Truncation
    // Verification should pass up to the truncated point, but if we expect 3 and get 2, we know it's truncated.
    // At the crypto layer, `verify_log_chain` just verifies what's given. The application layer checks lengths.
    let truncated = &store.entries[0..2];
    let dec_trunc = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, truncated).unwrap();
    assert_eq!(dec_trunc.len(), 2);
    
    // Attack 2: Rollback / Reordering
    let mut reordered = store.entries.clone();
    reordered.swap(1, 2);
    // Sequence numbers will be out of order -> should fail immediately
    let err = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &reordered).unwrap_err();
    assert!(matches!(err, E2EError::InvalidMessageFormat | E2EError::InvalidSignature));
    
    // Attack 3: Modification / Bit flip in ciphertext
    let mut corrupted = store.entries.clone();
    let last_idx = corrupted[1].ciphertext.len() - 1;
    corrupted[1].ciphertext[last_idx] ^= 1; // Flip bit in payload ciphertext
    
    let err2 = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &corrupted).unwrap_err();
    assert!(matches!(err2, E2EError::InvalidSignature | E2EError::MessageDecryptionFailed));

    // Attack 4: Hash chain modification
    let mut hash_corrupted = store.entries.clone();
    hash_corrupted[1].current_hash[0] ^= 1;
    let err3 = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &hash_corrupted).unwrap_err();
    // Because the hash of entry 1 doesn't match the actual hash
    assert!(matches!(err3, E2EError::InvalidSignature));
}
