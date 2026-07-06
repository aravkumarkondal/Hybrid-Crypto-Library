// Add to impl TreeKEM

    /// Calculates the resolution of a node: a list of non-blank node indices 
    /// that currently hold public keys covering this subtree.
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
