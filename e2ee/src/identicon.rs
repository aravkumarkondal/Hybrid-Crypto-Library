use alloc::vec::Vec;
use alloc::vec;
use crate::verification_visual::HybridFingerprint;

/// A deterministic geometric visual representation of an identity.
/// 
/// The core module outputs only a platform-independent `Vec<Vec<bool>>` matrix.
/// Adapters can map this raw boolean matrix into SVGs, PNGs, HTML, or native UI
/// elements without introducing graphics or serialization dependencies to the core.
pub struct Identicon {
    /// An 8x8 grid of boolean pixels (true = foreground, false = background).
    pub grid: Vec<Vec<bool>>,
}

impl Identicon {
    /// Generates an 8x8 vertically symmetric identicon grid from a fingerprint.
    ///
    /// The algorithm uses 32 bits of entropy from the fingerprint to color
    /// the left 4x8 block, which is then mirrored to the right 4x8 block
    /// to create aesthetically pleasing, vertically symmetric geometric patterns.
    #[must_use]
    pub fn generate(fingerprint: &HybridFingerprint) -> Self {
        let digest = fingerprint.as_bytes();
        
        // Initialize an 8x8 grid
        let mut grid = vec![vec![false; 8]; 8];
        
        let mut bit_index = 0;
        for row in 0..8 {
            for col in 0..4 {
                let byte_idx = bit_index / 8;
                let bit_in_byte = bit_index % 8;
                let is_set = (digest[byte_idx] & (1 << bit_in_byte)) != 0;
                
                // Set the left side
                grid[row][col] = is_set;
                // Set the mirrored right side
                grid[row][7 - col] = is_set;
                
                bit_index += 1;
            }
        }
        
        Self { grid }
    }
}
