extern crate alloc;

use e2ee::mls::treekem::TreeKEM;
use e2ee::errors::E2EError;

#[test]
fn test_treekem_exhaustive_paths() {
    let mut tree = TreeKEM::new(); // 8 leaves
    for i in 0..8 {
        let leaf_kp = e2ee::mls::treekem::TreeKEM::derive_keypair(&[i as u8; 32]);
        tree.add_leaf(e2ee::mls::treekem::NodePublicKey {
            ecc_public: leaf_kp.ecc_public,
            pqc_public: leaf_kp.pqc_public,
        });
    }
    
    // Test update with invalid ephemeral privs len
    let leaf_secret = [1u8; 32];
    let ephemeral_privs = alloc::vec![[2u8; 32]; 1]; // Not enough for all encryptions
    let kem_entropies = alloc::vec![[3u8; 32]; 1];
    
    let res = tree.update(0, &leaf_secret, &ephemeral_privs, &kem_entropies);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // Generate valid update path for member 0
    let ephemeral_privs = alloc::vec![[2u8; 32]; 20];
    let kem_entropies = alloc::vec![[3u8; 32]; 20];
    let mut path = tree.update(0, &leaf_secret, &ephemeral_privs, &kem_entropies).unwrap();
    
    // Process update for member 1
    // Member 1 doesn't have private keys in the tree yet, so it won't be able to decrypt the path secret
    // It should just apply the public keys.
    tree.process_update(&path).unwrap();
    
    // Truncate path nodes to test length check
    path.nodes.pop();
    let res = tree.process_update(&path);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
}

#[test]
fn test_treekem_decryption_failure_on_expected_pub_mismatch() {
    let mut tree = TreeKEM::new(); 
    for i in 0..8 {
        let leaf_kp = e2ee::mls::treekem::TreeKEM::derive_keypair(&[i as u8; 32]);
        tree.add_leaf(e2ee::mls::treekem::NodePublicKey {
            ecc_public: leaf_kp.ecc_public,
            pqc_public: leaf_kp.pqc_public,
        });
    }
    let leaf_secret = [1u8; 32];
    let ephemeral_privs = alloc::vec![[2u8; 32]; 20];
    let kem_entropies = alloc::vec![[3u8; 32]; 20];
    
    
    let mut path = tree.update(0, &leaf_secret, &ephemeral_privs, &kem_entropies).unwrap();
    
    // Mutate the expected public key in the update path
    path.nodes[0].public_key.ecc_public[0] ^= 0xFF;
    
    // Simulate member 1 processing member 0's update path (overlap at sibling leaf)
    let leaf_kp_1 = e2ee::mls::treekem::TreeKEM::derive_keypair(&[1u8; 32]);
    tree.nodes[e2ee::mls::treekem::TreeKEM::leaf_to_node(1) as usize].private_key = Some(leaf_kp_1);
    
    let res = tree.process_update(&path);
    assert!(res.is_err());
}
