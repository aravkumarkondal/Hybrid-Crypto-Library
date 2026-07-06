use alloc::vec::Vec;
use crate::prekeys::OneTimePreKeyPair;
use hybrid_crypto::hkdf::hkdf_expand;
use crate::errors::E2EError;
use hybrid_crypto::x25519::{x25519, x25519_base};
use hybrid_crypto::ml_kem::{ml_kem_768_encapsulate, ml_kem_768_decapsulate};
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::sha2::Sha256;

#[derive(Clone, PartialEq, Eq)]
pub struct NodePublicKey {
    pub ecc_public: [u8; 32],
    pub pqc_public: [u8; 1184], // ML-KEM-768
}

impl NodePublicKey {
    pub fn encrypt_secret(
        &self,
        secret: &[u8; 32],
        ephemeral_ecc_private: &[u8; 32],
        kem_entropy: &[u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32], [u8; 1088]), E2EError> { // (ciphertext, ephemeral_pub, kem_ct)
        let ephemeral_ecc_public = x25519_base(ephemeral_ecc_private);
        let dh_shared = x25519(ephemeral_ecc_private, &self.ecc_public).map_err(|_| E2EError::EncryptionError)?;
        let (kem_ct, kem_shared) = ml_kem_768_encapsulate(&self.pqc_public, kem_entropy).map_err(|_| E2EError::EncryptionError)?;

        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&dh_shared);
        kdf_input.extend_from_slice(&kem_shared);

        let mut hasher = Sha256::new();
        hasher.update(&kdf_input);
        let prk = hasher.finalize();

        let mut aes_key = [0u8; 32];
        hkdf_expand(&prk, b"TREEKEM_NODE_KEY", &mut aes_key);

        let iv = [0u8; 12];
        let mut ciphertext = alloc::vec![0u8; 32];
        let auth_tag = aes256_gcm_encrypt(&aes_key, &iv, b"", secret, &mut ciphertext);
        
        ciphertext.extend_from_slice(&auth_tag);

        Ok((ciphertext, ephemeral_ecc_public, kem_ct))
    }
}

#[derive(Clone)]
#[derive(Default)]
pub struct Node {
    pub public_key: Option<NodePublicKey>,
    pub private_key: Option<OneTimePreKeyPair>,
    pub parent_hash: Option<[u8; 32]>,
}

impl Node {
    pub fn decrypt_secret(
        &self,
        ciphertext: &[u8],
        ephemeral_ecc_public: &[u8; 32],
        kem_ct: &[u8; 1088],
    ) -> Result<[u8; 32], E2EError> {
        let priv_key = self.private_key.as_ref().ok_or(E2EError::DecryptionError)?;
        
        let dh_shared = x25519(&priv_key.ecc_private, ephemeral_ecc_public).map_err(|_| E2EError::DecryptionError)?;
        let kem_shared = ml_kem_768_decapsulate(&priv_key.pqc_private, kem_ct);
        
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&dh_shared);
        kdf_input.extend_from_slice(&kem_shared);

        let mut hasher = Sha256::new();
        hasher.update(&kdf_input);
        let prk = hasher.finalize();

        let mut aes_key = [0u8; 32];
        hkdf_expand(&prk, b"TREEKEM_NODE_KEY", &mut aes_key);

        if ciphertext.len() < 16 {
            return Err(E2EError::InvalidMessageFormat);
        }
        
        let ct = &ciphertext[..ciphertext.len() - 16];
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
        
        let mut secret = hybrid_crypto::utils::SecretKey(alloc::vec![0u8; ct.len()]);
        
        aes256_gcm_decrypt(
            &aes_key,
            &[0u8; 12], // Zero IV is safe because the AES key is single-use for this specific ephemeral exchange
            b"",
            ct,
            &auth_tag,
            &mut secret,
        ).map_err(|_| E2EError::DecryptionError)?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&secret.0);
        Ok(result)
    }
}


#[derive(Clone)]
pub struct TreeKEM {
    pub num_leaves: u32,
    pub nodes: Vec<Node>,
}

impl Default for TreeKEM {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeKEM {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            num_leaves: 0,
            nodes: Vec::new(),
        }
    }

    /// LBBT Math: Leaf index to node index
    #[must_use]
    pub const fn leaf_to_node(leaf_index: u32) -> u32 {
        leaf_index * 2
    }

    /// LBBT Math: Is the node index a leaf?
    #[must_use]
    pub const fn is_leaf(node_index: u32) -> bool {
        node_index.is_multiple_of(2)
    }

    /// Derives a keypair from a 32-byte path secret
    #[must_use]
    pub fn derive_keypair(path_secret: &[u8; 32]) -> OneTimePreKeyPair {
        let mut ecc_entropy = [0u8; 32];
        let mut pqc_entropy = [0u8; 64];

        hkdf_expand(path_secret, b"TREEKEM_ECC", &mut ecc_entropy);
        hkdf_expand(path_secret, b"TREEKEM_PQC", &mut pqc_entropy);

        OneTimePreKeyPair::generate(0, &ecc_entropy, &pqc_entropy)
    }

    /// Derives the parent path secret from a child path secret
    #[must_use]
    pub fn derive_parent_secret(path_secret: &[u8; 32]) -> [u8; 32] {
        let mut parent_secret = [0u8; 32];
        hkdf_expand(path_secret, b"TREEKEM_PARENT", &mut parent_secret);
        parent_secret
    }

    /// Number of nodes in a tree with `num_leaves` leaves
    #[must_use]
    pub const fn node_count(num_leaves: u32) -> u32 {
        if num_leaves == 0 {
            0
        } else {
            2 * num_leaves - 1
        }
    }

    /// The level of a node
    #[must_use]
    pub const fn level(x: u32) -> u32 {
        if x.is_multiple_of(2) {
            return 0;
        }
        let mut k = 0;
        let temp = x;
        while (temp >> k) & 1 == 1 {
            k += 1;
        }
        k
    }

    /// LBBT Math: Integer logarithm base 2
    #[must_use]
    pub const fn log2(x: u32) -> u32 {
        if x == 0 {
            return 0;
        }
        x.ilog2()
    }

    /// LBBT root calculation for `n` nodes
    #[must_use]
    pub fn root(n: u32) -> u32 {
        if n == 0 {
            return 0; // Invalid
        }
        (1 << Self::log2(n)) - 1
    }

    /// Parent of node `x` in a tree with `n` nodes
    #[must_use]
    pub fn parent(x: u32, n: u32) -> u32 {
        if x == Self::root(n) {
            return x;
        }
        let mut b = Self::level(x);
        let mut p = (x | (1 << b)) & !(1 << (b + 1));
        while p >= n {
            b += 1;
            p = (p | (1 << b)) & !(1 << (b + 1));
        }
        p
    }

    /// Left child of node `x`
    #[must_use]
    pub fn left(x: u32) -> u32 {
        let k = Self::level(x);
        if k == 0 {
            return x;
        }
        x ^ (1 << (k - 1))
    }

    /// Right child of node `x` in a tree with `n` nodes
    #[must_use]
    pub fn right(x: u32, n: u32) -> u32 {
        let k = Self::level(x);
        if k == 0 {
            return x;
        }
        let mut r = x ^ (3 << (k - 1));
        while r >= n {
            r = Self::left(r);
        }
        r
    }

    /// Direct path from `x` (inclusive) to root (inclusive)
    #[must_use]
    pub fn dirpath(x: u32, n: u32) -> Vec<u32> {
        let mut path = Vec::new();
        let mut current = x;
        let root_idx = Self::root(n);
        
        path.push(current);
        while current != root_idx {
            current = Self::parent(current, n);
            path.push(current);
        }
        path
    }

    /// Copath of `x`: the siblings of the nodes in the dirpath
    #[must_use]
    pub fn copath(x: u32, n: u32) -> Vec<u32> {
        let mut path = Vec::new();
        let mut current = x;
        let root_idx = Self::root(n);
        
        while current != root_idx {
            let p = Self::parent(current, n);
            let l = Self::left(p);
            let r = Self::right(p, n);
            
            if current == l {
                path.push(r);
            } else {
                path.push(l);
            }
            current = p;
        }
        path
    }

    /// Calculates the resolution of a node: a list of non-blank node indices 
    /// that currently hold public keys covering this subtree.
    #[must_use]
    pub fn resolve(&self, x: u32, n: u32) -> Vec<u32> {
        if self.nodes[x as usize].public_key.is_some() {
            return alloc::vec![x];
        }
        if Self::is_leaf(x) {
            return alloc::vec![];
        }
        let mut res = Vec::new();
        res.extend(self.resolve(Self::left(x), n));
        res.extend(self.resolve(Self::right(x, n), n));
        res
    }

    /// Adds a leaf to the tree and returns its index. 
    /// This also blanks out the direct path to maintain tree invariants.
    pub fn add_leaf(&mut self, public_key: NodePublicKey) -> u32 {
        let leaf_index = self.num_leaves;
        self.num_leaves += 1;
        let n = Self::node_count(self.num_leaves);
        
        // Resize nodes array
        self.nodes.resize(n as usize, Node::default());
        
        let node_index = Self::leaf_to_node(leaf_index);
        self.nodes[node_index as usize].public_key = Some(public_key);

        // Blank out the direct path
        let dirpath = Self::dirpath(node_index, n);
        for i in 1..dirpath.len() { // Skip the leaf itself
            let idx = dirpath[i] as usize;
            self.nodes[idx].public_key = None;
            self.nodes[idx].private_key = None;
        }

        leaf_index
    }

    /// Removes a leaf by blanking it and its direct path.
    pub fn remove_leaf(&mut self, leaf_index: u32) {
        let n = Self::node_count(self.num_leaves);
        if leaf_index >= self.num_leaves {
            return;
        }
        
        let node_index = Self::leaf_to_node(leaf_index);
        let dirpath = Self::dirpath(node_index, n);
        
        for idx in dirpath {
            self.nodes[idx as usize].public_key = None;
            self.nodes[idx as usize].private_key = None;
        }
    }
}

#[derive(Clone)]
pub struct EncryptedSecret {
    pub target_node: u32,
    pub ciphertext: Vec<u8>,
    pub ephemeral_ecc_public: [u8; 32],
    pub kem_ct: [u8; 1088],
}

#[derive(Clone)]
pub struct UpdatePathNode {
    pub public_key: NodePublicKey,
    pub encrypted_parent_secrets: Vec<EncryptedSecret>,
}

#[derive(Clone)]
pub struct UpdatePath {
    pub leaf_index: u32,
    pub nodes: Vec<UpdatePathNode>,
}

impl TreeKEM {
    /// Generates an update path for a given leaf
    pub fn update(
        &mut self,
        leaf_index: u32,
        leaf_secret: &[u8; 32],
        ephemeral_privs: &[[u8; 32]],
        kem_entropies: &[[u8; 32]],
    ) -> Result<UpdatePath, E2EError> {
        let n = Self::node_count(self.num_leaves);
        let node_index = Self::leaf_to_node(leaf_index);
        let dirpath = Self::dirpath(node_index, n);
        let copath = Self::copath(node_index, n);

        let total_encryptions = copath.iter().map(|&c| self.resolve(c, n).len()).sum::<usize>();

        if ephemeral_privs.len() < total_encryptions || kem_entropies.len() < total_encryptions {
            return Err(E2EError::InvalidMessageFormat);
        }

        let mut path_nodes = Vec::new();
        let mut current_secret = *leaf_secret;
        let mut enc_idx = 0;

        // Update own leaf
        let leaf_keypair = Self::derive_keypair(&current_secret);
        self.nodes[node_index as usize].public_key = Some(NodePublicKey {
            ecc_public: leaf_keypair.ecc_public,
            pqc_public: leaf_keypair.pqc_public,
        });
        self.nodes[node_index as usize].private_key = Some(leaf_keypair);

        // Process dirpath
        for i in 0..(dirpath.len() - 1) {
            let parent_secret = Self::derive_parent_secret(&current_secret);
            let parent_idx = dirpath[i + 1] as usize;
            
            // Derive parent keypair
            let parent_keypair = Self::derive_keypair(&parent_secret);
            let parent_pub = NodePublicKey {
                ecc_public: parent_keypair.ecc_public,
                pqc_public: parent_keypair.pqc_public,
            };

            // Update local tree
            self.nodes[parent_idx].public_key = Some(parent_pub.clone());
            self.nodes[parent_idx].private_key = Some(parent_keypair);

            // Encrypt parent secret for the resolution of the copath node
            let copath_idx = copath[i];
            let resolution = self.resolve(copath_idx, n);
            
            let mut encrypted_secrets = Vec::new();
            for &target_node in &resolution {
                if let Some(target_pub) = &self.nodes[target_node as usize].public_key {
                    let (ciphertext, ephemeral_pub, kem_ct) = target_pub.encrypt_secret(
                        &parent_secret,
                        &ephemeral_privs[enc_idx],
                        &kem_entropies[enc_idx],
                    )?;
                    enc_idx += 1;
                    
                    encrypted_secrets.push(EncryptedSecret {
                        target_node,
                        ciphertext,
                        ephemeral_ecc_public: ephemeral_pub,
                        kem_ct,
                    });
                }
            }

            path_nodes.push(UpdatePathNode {
                public_key: parent_pub,
                encrypted_parent_secrets: encrypted_secrets,
            });

            current_secret = parent_secret;
        }

        Ok(UpdatePath {
            leaf_index,
            nodes: path_nodes,
        })
    }

    /// Process an update path from another member
    pub fn process_update(&mut self, path: &UpdatePath) -> Result<(), E2EError> {
        let n = Self::node_count(self.num_leaves);
        let node_index = Self::leaf_to_node(path.leaf_index);
        let dirpath = Self::dirpath(node_index, n);
        let copath = Self::copath(node_index, n);

        if path.nodes.len() != dirpath.len() - 1 {
            return Err(E2EError::InvalidMessageFormat);
        }

        // Apply public keys from the update path to our tree
        for i in 0..path.nodes.len() {
            let parent_idx = dirpath[i + 1] as usize;
            self.nodes[parent_idx].public_key = Some(path.nodes[i].public_key.clone());
        }

        // Find the overlap where we can decrypt the path secret
        let mut decrypted_secret = None;
        let mut overlap_index = 0;

        for i in 0..copath.len() {
            let cp_idx = copath[i];
            let resolution = self.resolve(cp_idx, n);
            
            // Check if we have the private key for any node in the resolution
            for &target_node in &resolution {
                if self.nodes[target_node as usize].private_key.is_some() {
                    let node_data = &path.nodes[i];
                    // Find the ciphertext for this target_node
                    if let Some(enc_secret) = node_data.encrypted_parent_secrets.iter().find(|e| e.target_node == target_node) {
                        let secret = self.nodes[target_node as usize].decrypt_secret(
                            &enc_secret.ciphertext,
                            &enc_secret.ephemeral_ecc_public,
                            &enc_secret.kem_ct,
                        )?;
                        decrypted_secret = Some(secret);
                        overlap_index = i;
                        break;
                    }
                }
            }
            if decrypted_secret.is_some() {
                break;
            }
        }

        if let Some(mut current_secret) = decrypted_secret {
            // We decrypted the secret for dirpath[overlap_index + 1]
            // We now derive and store private keys from this point up to the root
            for i in overlap_index..(dirpath.len() - 1) {
                let parent_idx = dirpath[i + 1] as usize;
                let parent_keypair = Self::derive_keypair(&current_secret);
                
                // Verify public key matches
                let expected_pub = &path.nodes[i].public_key;
                if parent_keypair.ecc_public != expected_pub.ecc_public || parent_keypair.pqc_public != expected_pub.pqc_public {
                    return Err(E2EError::DecryptionError);
                }

                self.nodes[parent_idx].private_key = Some(parent_keypair);
                
                if i < dirpath.len() - 2 {
                    current_secret = Self::derive_parent_secret(&current_secret);
                }
            }
        }

        // Note: The leaf node (dirpath[0])'s public key is updated via a separate mechanism (or we can include it in UpdatePath)
        // For standard TreeKEM, the leaf's public key is broadcast alongside the UpdatePath.
        Ok(())
    }
}
