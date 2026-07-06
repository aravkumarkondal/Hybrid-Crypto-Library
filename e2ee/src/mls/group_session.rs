use alloc::vec::Vec;
use crate::mls::treekem::{TreeKEM, UpdatePath};
use crate::errors::E2EError;
use hybrid_crypto::hkdf::hkdf_expand;
use crate::sender_keys::SenderKeyChain;

pub struct HybridGroupSession {
    pub tree: TreeKEM,
    pub member_index: u32,
    pub epoch_secret: [u8; 32],
    pub local_chain: SenderKeyChain,
    pub peer_chains: Vec<Option<SenderKeyChain>>,
}

impl HybridGroupSession {
    #[must_use]
    pub fn new(tree: TreeKEM, member_index: u32, initial_epoch_secret: [u8; 32]) -> Self {
        let n = tree.num_leaves;
        let mut session = Self {
            tree,
            member_index,
            epoch_secret: initial_epoch_secret,
            local_chain: SenderKeyChain::new(&[0u8; 32], 0),
            peer_chains: Vec::new(),
        };
        session.peer_chains.resize(n as usize, None);
        session.rotate_epoch(initial_epoch_secret);
        session
    }

    /// Derives new `SenderKey` chains for the group based on the new epoch secret.
    fn rotate_epoch(&mut self, new_epoch_secret: [u8; 32]) {
        self.epoch_secret = new_epoch_secret;
        
        let n = self.tree.num_leaves;
        self.peer_chains.resize(n as usize, None);
        
        for i in 0..n {
            let mut derived_key = [0u8; 32];
            let mut info = Vec::new();
            info.extend_from_slice(b"GROUP_MEMBER_");
            info.extend_from_slice(&i.to_be_bytes());
            
            hkdf_expand(&self.epoch_secret, &info, &mut derived_key);
            
            let chain = SenderKeyChain::new(&derived_key, 0);
            if i == self.member_index {
                self.local_chain = chain;
            } else {
                self.peer_chains[i as usize] = Some(chain);
            }
        }
    }

    pub fn update(
        &mut self,
        leaf_secret: &[u8; 32],
        ephemeral_privs: &[[u8; 32]],
        kem_entropies: &[[u8; 32]],
    ) -> Result<UpdatePath, E2EError> {
        let path = self.tree.update(self.member_index, leaf_secret, ephemeral_privs, kem_entropies)?;
        
        // Derive new epoch secret from the new root secret
        let root_idx = TreeKEM::root(TreeKEM::node_count(self.tree.num_leaves)) as usize;
        if let Some(priv_key) = &self.tree.nodes[root_idx].private_key {
            // Note: in a real implementation, the root secret would be cryptographically derived from the TreeKEM root path secret.
            // For now, we simulate this by deriving the epoch secret from the root's ECC private key (since it's fresh and shared).
            let mut new_epoch_secret = [0u8; 32];
            hkdf_expand(&priv_key.ecc_private, b"NEW_EPOCH", &mut new_epoch_secret);
            
            self.rotate_epoch(new_epoch_secret);
        } else {
            return Err(E2EError::DecryptionError); // Should not happen since we just updated
        }
        
        Ok(path)
    }

    pub fn process_update(&mut self, path: &UpdatePath) -> Result<(), E2EError> {
        self.tree.process_update(path)?;
        
        let root_idx = TreeKEM::root(TreeKEM::node_count(self.tree.num_leaves)) as usize;
        if let Some(priv_key) = &self.tree.nodes[root_idx].private_key {
            let mut new_epoch_secret = [0u8; 32];
            hkdf_expand(&priv_key.ecc_private, b"NEW_EPOCH", &mut new_epoch_secret);
            
            self.rotate_epoch(new_epoch_secret);
        } else {
            return Err(E2EError::DecryptionError); // We failed to decrypt the path
        }
        
        Ok(())
    }
}
