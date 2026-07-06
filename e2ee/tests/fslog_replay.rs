extern crate alloc;

use e2ee::fslog::{FsLogStore};
use e2ee::errors::E2EError;
use alloc::vec::Vec;

#[test]
fn test_fslog_replay_resistance() {
    let genesis_key = [10u8; 32];
    let genesis_hash = [11u8; 32];
    
    let mut store = FsLogStore::new(&genesis_key, &genesis_hash);
    
    store.append(b"Event 1", 2000).unwrap();
    store.append(b"Event 2", 2005).unwrap();
    store.append(b"Event 3", 2010).unwrap();
    
    // Replay attack: Duplicating an entry
    let mut replayed = store.entries.clone();
    replayed.insert(2, store.entries[1].clone()); // Replay Event 2 at position 2
    
    // This should fail because the sequence number of the duplicated entry will be 1, but we expect 2.
    // AND the hash chain will break because it's hashing H(1) || E(2) where E(2) is the duplicated E(1).
    let err = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &replayed).unwrap_err();
    assert!(matches!(err, E2EError::InvalidMessageFormat | E2EError::InvalidSignature));

    // Advanced Replay: Appending a valid older chain
    // Attacker takes an older valid log and appends it to a newer one
    let mut appended_replay = store.entries.clone();
    appended_replay.push(store.entries[0].clone());

    let err2 = FsLogStore::verify_log_chain(&genesis_key, &genesis_hash, &appended_replay).unwrap_err();
    assert!(matches!(err2, E2EError::InvalidMessageFormat | E2EError::InvalidSignature));
}
