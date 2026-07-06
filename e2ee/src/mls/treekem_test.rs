#[cfg(test)]
mod tests {
    use crate::mls::treekem::*;
    use alloc::vec;
    

    #[test]
    fn test_treekem_update_and_derive() {
        let mut alice_tree = TreeKEM::new();
        
        let alice_secret = [1u8; 32];
        let alice_keypair = TreeKEM::derive_keypair(&alice_secret);
        let alice_pub = NodePublicKey {
            ecc_public: alice_keypair.ecc_public,
            pqc_public: alice_keypair.pqc_public,
        };
        
        let bob_secret = [2u8; 32];
        let bob_keypair = TreeKEM::derive_keypair(&bob_secret);
        let bob_pub = NodePublicKey {
            ecc_public: bob_keypair.ecc_public,
            pqc_public: bob_keypair.pqc_public,
        };

        let alice_idx = alice_tree.add_leaf(alice_pub.clone());
        let bob_idx = alice_tree.add_leaf(bob_pub.clone());

        // Alice knows her private key
        alice_tree.nodes[TreeKEM::leaf_to_node(alice_idx) as usize].private_key = Some(alice_keypair.clone());

        // Bob has his own tree state
        let mut bob_tree = TreeKEM::new();
        bob_tree.add_leaf(alice_pub.clone());
        bob_tree.add_leaf(bob_pub.clone());
        bob_tree.nodes[TreeKEM::leaf_to_node(bob_idx) as usize].private_key = Some(bob_keypair.clone());

        // Alice updates her leaf
        let new_alice_secret = [3u8; 32];
        let ephemeral_privs = vec![[4u8; 32]; 10];
        let kem_entropies = vec![[5u8; 32]; 10];
        
        let update_path = alice_tree.update(
            alice_idx,
            &new_alice_secret,
            &ephemeral_privs,
            &kem_entropies,
        ).unwrap();

        // Bob processes the update
        bob_tree.process_update(&update_path).unwrap();

        // Both trees should now have the exact same root node public key and private key (since they can both derive it)
        let root_idx = TreeKEM::root(TreeKEM::node_count(2)) as usize;
        let alice_root_pub = alice_tree.nodes[root_idx].public_key.as_ref().unwrap();
        let bob_root_pub = bob_tree.nodes[root_idx].public_key.as_ref().unwrap();

        assert_eq!(alice_root_pub.ecc_public, bob_root_pub.ecc_public);
        assert_eq!(alice_root_pub.pqc_public, bob_root_pub.pqc_public);

        let alice_root_priv = alice_tree.nodes[root_idx].private_key.as_ref().unwrap();
        let bob_root_priv = bob_tree.nodes[root_idx].private_key.as_ref().unwrap();

        assert_eq!(alice_root_priv.ecc_private, bob_root_priv.ecc_private);
        assert_eq!(alice_root_priv.pqc_private, bob_root_priv.pqc_private);
    }
}
