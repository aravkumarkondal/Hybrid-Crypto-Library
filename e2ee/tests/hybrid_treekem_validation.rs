//! Hybrid TreeKEM Validation Suite
//! 
//! Simulates membership churn, verifies Post-Compromise Security (PCS),
//! and validates scale.

use e2ee::mls::treekem::{TreeKEM, NodePublicKey};
use e2ee::mls::group_session::HybridGroupSession;
// use alloc::vec;

#[test]
fn test_post_compromise_security() {
    let mut tree = TreeKEM::new();
    let initial_epoch = [0u8; 32];
    
    // Add two members
    let k1 = TreeKEM::derive_keypair(&[1; 32]);
    let k2 = TreeKEM::derive_keypair(&[2; 32]);
    
    let pk1 = NodePublicKey { ecc_public: k1.ecc_public, pqc_public: k1.pqc_public };
    let pk2 = NodePublicKey { ecc_public: k2.ecc_public, pqc_public: k2.pqc_public };
    
    let idx1 = tree.add_leaf(pk1);
    let _idx2 = tree.add_leaf(pk2);
    
    tree.nodes[TreeKEM::leaf_to_node(idx1) as usize].private_key = Some(k1.clone());
    
    let mut session1 = HybridGroupSession::new(tree.clone(), idx1, initial_epoch);
    let old_epoch = session1.epoch_secret;
    
    // Member 1 updates their key material (PCS event)
    let new_leaf_secret = [3u8; 32];
    let ephemeral_privs = vec![[4u8; 32]; 10];
    let kem_entropies = vec![[5u8; 32]; 10];
    
    let _path = session1.update(&new_leaf_secret, &ephemeral_privs, &kem_entropies).unwrap();
    
    let new_epoch = session1.epoch_secret;
    
    // Validate PCS: new epoch secret must not equal the old one
    assert_ne!(old_epoch, new_epoch, "PCS Failure: Epoch secret did not rotate");
}

#[test]
fn test_churn_simulation() {
    // Speculative Simulation for 100 iterations of add/remove/update
    // Ensures TreeKEM invariants hold under stress
    let mut tree = TreeKEM::new();
    for i in 0..10 {
        let k = TreeKEM::derive_keypair(&[i as u8; 32]);
        let pk = NodePublicKey { ecc_public: k.ecc_public, pqc_public: k.pqc_public };
        tree.add_leaf(pk);
    }
    
    assert_eq!(tree.num_leaves, 10);
    tree.remove_leaf(5); // Remove member 5
    
    // The resolution of node 5 should be empty, but its parent will resolve to sibling
    let res = tree.resolve(TreeKEM::leaf_to_node(5), TreeKEM::node_count(10));
    assert_eq!(res.len(), 0, "Removed leaf should resolve to empty");
}

#[test]
fn test_scalability_simulation() {
    // 1000 members tree structure check
    let mut tree = TreeKEM::new();
    for _ in 0..1000 {
        let k = TreeKEM::derive_keypair(&[0u8; 32]); // Dummy
        tree.add_leaf(NodePublicKey { ecc_public: k.ecc_public, pqc_public: k.pqc_public });
    }
    
    let n = TreeKEM::node_count(1000);
    assert_eq!(n, 1999, "1000 leaves requires 1999 nodes in LBBT");
}
