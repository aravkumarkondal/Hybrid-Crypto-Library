use alloc::vec::Vec;
use hybrid_crypto::sha2::Sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleNode(pub [u8; 32]);

/// A simple append-only Merkle Tree for Key Transparency Log simulation.
pub struct KeyTransparencyLog {
    leaves: Vec<MerkleNode>,
}

impl Default for KeyTransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyTransparencyLog {
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Appends a new serialized key/device payload to the log.
    pub fn append(&mut self, payload: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(b"0x00"); // Leaf prefix
        hasher.update(payload);
        self.leaves.push(MerkleNode(hasher.finalize()));
    }

    /// Computes the current root of the Merkle Tree.
    #[must_use]
    pub fn root(&self) -> MerkleNode {
        if self.leaves.is_empty() {
            return MerkleNode([0u8; 32]);
        }
        self.compute_root(&self.leaves)
    }

    fn compute_root(&self, nodes: &[MerkleNode]) -> MerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }

        let mut next_level = Vec::new();
        for chunk in nodes.chunks(2) {
            if chunk.len() == 2 {
                let mut hasher = Sha256::new();
                hasher.update(b"0x01"); // Internal node prefix
                hasher.update(&chunk[0].0);
                hasher.update(&chunk[1].0);
                next_level.push(MerkleNode(hasher.finalize()));
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        self.compute_root(&next_level)
    }

    /// Generates an inclusion proof for the leaf at `index`.
    #[must_use]
    pub fn prove_inclusion(&self, index: usize) -> Vec<MerkleNode> {
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index].clone());
            }

            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(b"0x01");
                    hasher.update(&chunk[0].0);
                    hasher.update(&chunk[1].0);
                    next_level.push(MerkleNode(hasher.finalize()));
                } else {
                    next_level.push(chunk[0].clone());
                }
            }
            current_level = next_level;
            current_index /= 2;
        }

        proof
    }

    /// Verifies an inclusion proof. 
    /// Given a leaf payload, its index, the proof, and the expected root, this returns true if valid.
    #[must_use]
    pub fn verify_inclusion(
        payload: &[u8],
        mut index: usize,
        proof: &[MerkleNode],
        expected_root: &MerkleNode,
    ) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(b"0x00");
        hasher.update(payload);
        let mut current_hash = hasher.finalize();

        for sibling in proof {
            let mut hasher = Sha256::new();
            hasher.update(b"0x01");
            if index.is_multiple_of(2) {
                hasher.update(&current_hash);
                hasher.update(&sibling.0);
            } else {
                hasher.update(&sibling.0);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize();
            index /= 2;
        }

        current_hash == expected_root.0
    }
}
