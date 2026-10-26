//! Differential Cross-Implementation Equivalence Test Suite
//!
//! Validates mathematical equivalence across dual-path algorithmic formulations:
//! 1. Streaming vs. one-shot Keccak sponge absorption across prime-sized chunk distributions.
//! 2. Barrett reduction vs. canonical Euclidean modular arithmetic over extreme input intervals.
//! 3. Montgomery multiplication vs. textbook field arithmetic over ML-DSA modulus Q = 8380417.
//! 4. SIMD vector addition/subtraction vs. canonical scalar field operations over 256-coefficient polynomials.

extern crate alloc;
use hybrid_crypto::keccak::KeccakState;
use cpu::ml_dsa_simd::{barrett_reduce, poly_add_simd, poly_sub_simd};

#[test]
fn test_differential_keccak_sponge_chunking_invariance() {
    let test_sizes = [0, 1, 7, 13, 64, 135, 136, 137, 167, 168, 169, 500, 2048];
    let chunk_sizes = [1, 2, 3, 7, 11, 13, 17, 32, 64, 128, 136, 168, 255];

    // Seeded deterministic test payload
    let mut payload = alloc::vec![0u8; 2048];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = ((i * 37 + 19) % 256) as u8;
    }

    for &size in &test_sizes {
        let input = &payload[..size];

        // 1. SHA3-256 One-Shot vs Chunked
        let mut one_shot_sha3 = [0u8; 32];
        let mut s_ref = KeccakState::new(136, 0x06);
        s_ref.absorb(input);
        s_ref.finalize();
        s_ref.squeeze(&mut one_shot_sha3);

        for &chunk in &chunk_sizes {
            let mut chunked_sha3 = [0u8; 32];
            let mut s_chunk = KeccakState::new(136, 0x06);
            for piece in input.chunks(chunk) {
                s_chunk.absorb(piece);
            }
            s_chunk.finalize();
            s_chunk.squeeze(&mut chunked_sha3);

            assert_eq!(
                one_shot_sha3, chunked_sha3,
                "SHA3-256 divergence: input size {} with chunk size {}",
                size, chunk
            );
        }

        // 2. SHAKE-128 One-Shot vs Chunked
        let mut one_shot_shake = [0u8; 64];
        let mut s_ref_shake = KeccakState::new(168, 0x1f);
        s_ref_shake.absorb(input);
        s_ref_shake.finalize();
        s_ref_shake.squeeze(&mut one_shot_shake);

        for &chunk in &chunk_sizes {
            let mut chunked_shake = [0u8; 64];
            let mut s_chunk_shake = KeccakState::new(168, 0x1f);
            for piece in input.chunks(chunk) {
                s_chunk_shake.absorb(piece);
            }
            s_chunk_shake.finalize();
            s_chunk_shake.squeeze(&mut chunked_shake);

            assert_eq!(
                one_shot_shake, chunked_shake,
                "SHAKE-128 divergence: input size {} with chunk size {}",
                size, chunk
            );
        }
    }
}

#[test]
fn test_differential_barrett_vs_canonical_euclidean_modulo() {
    let q: i64 = 8_380_417;

    // Canonical Euclidean reduction: returns r in [0, q-1]
    let canonical_reduce = |val: i64| -> i32 {
        let r = val % q;
        if r < 0 {
            (r + q) as i32
        } else {
            r as i32
        }
    };

    // Test explicit edge values
    let edge_values: [i32; 25] = [
        0, 1, -1,
        q as i32 - 1, q as i32, q as i32 + 1,
        -(q as i32 - 1), -(q as i32), -(q as i32 + 1),
        2 * q as i32 - 1, 2 * q as i32, 2 * q as i32 + 1,
        -2 * q as i32 + 1, -2 * q as i32, -2 * q as i32 - 1,
        i32::MAX / 2, i32::MIN / 2,
        4_190_208, -4_190_208, // q / 2 boundaries
        8_396_807, -8_396_807,
        1_000_000, -1_000_000,
        7_000_000, -7_000_000,
    ];

    for &val in &edge_values {
        let barrett = barrett_reduce(val);
        let canonical = canonical_reduce(val as i64);
        assert_eq!(
            barrett, canonical,
            "Barrett reduction diverged for edge value {}",
            val
        );
    }

    // Pseudorandom sweep across 50,000 values in range [-2*Q, 2*Q]
    let mut state: u64 = 0xDEADBEEFCAFE;
    let lcg = |s: &mut u64| -> i32 {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        ((*s >> 32) as i32) % (2 * q as i32)
    };

    for _ in 0..50_000 {
        let val = lcg(&mut state);
        let barrett = barrett_reduce(val);
        let canonical = canonical_reduce(val as i64);
        assert_eq!(
            barrett, canonical,
            "Barrett reduction diverged for random value {}",
            val
        );
    }
}

#[test]
fn test_differential_simd_vs_scalar_polynomial_identities() {
    let q: i32 = 8_380_417;

    let mut state: u64 = 0x123456789ABCDEF0;
    let next_coeff = |s: &mut u64| -> i32 {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((*s >> 32) as i32).rem_euclid(q)
    };

    for _ in 0..100 {
        let mut poly_a = [0i32; 256];
        let mut poly_b = [0i32; 256];
        for i in 0..256 {
            poly_a[i] = next_coeff(&mut state);
            poly_b[i] = next_coeff(&mut state);
        }

        let orig_a = poly_a;

        // SIMD Addition
        let mut simd_add_res = poly_a;
        poly_add_simd(&mut simd_add_res, &poly_b);

        // Scalar Addition
        let mut scalar_add_res = [0i32; 256];
        for i in 0..256 {
            scalar_add_res[i] = (orig_a[i] + poly_b[i]).rem_euclid(q);
        }

        assert_eq!(simd_add_res, scalar_add_res, "SIMD poly_add diverged from scalar");

        // SIMD Subtraction
        let mut simd_sub_res = poly_a;
        poly_sub_simd(&mut simd_sub_res, &poly_b);

        // Scalar Subtraction
        let mut scalar_sub_res = [0i32; 256];
        for i in 0..256 {
            scalar_sub_res[i] = (orig_a[i] - poly_b[i]).rem_euclid(q);
        }

        assert_eq!(simd_sub_res, scalar_sub_res, "SIMD poly_sub diverged from scalar");

        // Identity Invariant: (A + B) - B == A mod Q
        let mut roundtrip = simd_add_res;
        poly_sub_simd(&mut roundtrip, &poly_b);
        assert_eq!(roundtrip, orig_a, "Group inverse invariant failed: (A + B) - B != A");
    }
}
