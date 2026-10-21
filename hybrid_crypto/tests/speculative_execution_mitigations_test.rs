use hybrid_crypto::utils::{
    speculation_barrier,
    speculative_sanitize_index,
    speculative_ct_lookup_u8,
    cswap,
    constant_time_eq,
};

#[test]
fn test_speculation_barrier_execution() {
    // Verify that the architecture-specific speculation barrier (LFENCE on x86_64, CSDB on ARM64)
    // executes cleanly in loops without crashing or causing illegal instruction traps.
    for _ in 0..10_000 {
        speculation_barrier();
    }
}

#[test]
fn test_speculative_sanitize_index_bounds_enforcement() {
    let len = 64;

    // In-bounds indices must be preserved exactly
    for i in 0..len {
        let safe_idx = speculative_sanitize_index(i, len);
        assert_eq!(safe_idx, i, "In-bounds index {} must be preserved", i);
    }

    // Out-of-bounds indices must be clamped to 0 under speculation barriers
    // preventing speculative OOB reads and cache line pollution
    let oob_indices = [64, 65, 128, 1000, usize::MAX - 1, usize::MAX];
    for &oob in &oob_indices {
        let clamped = speculative_sanitize_index(oob, len);
        assert_eq!(clamped, 0, "Out-of-bounds index {} must be speculatively clamped to 0", oob);
    }
}

#[test]
fn test_speculative_constant_time_lookup_correctness_and_cache_neutrality() {
    let table = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    // Every in-bounds index must return the exact table value
    for i in 0..table.len() {
        let val = speculative_ct_lookup_u8(&table, i);
        assert_eq!(val, table[i], "Lookup at index {} failed", i);
    }

    // Out-of-bounds lookup returns table[0] clamped safely without panicking or leaking memory
    let oob_val = speculative_ct_lookup_u8(&table, 9999);
    assert_eq!(oob_val, table[0]);
}

#[test]
fn test_cswap_with_speculation_barrier() {
    let mut a = [100u64, 200, 300, 400];
    let mut b = [500u64, 600, 700, 800];

    let orig_a = a;
    let orig_b = b;

    // Swap = 0 -> no change
    cswap(0, &mut a, &mut b);
    assert_eq!(a, orig_a);
    assert_eq!(b, orig_b);

    // Swap = 1 -> swapped
    cswap(1, &mut a, &mut b);
    assert_eq!(a, orig_b);
    assert_eq!(b, orig_a);

    // Swap = 1 again -> back to original
    cswap(1, &mut a, &mut b);
    assert_eq!(a, orig_a);
    assert_eq!(b, orig_b);
}

#[test]
fn test_constant_time_eq_with_speculation_barrier() {
    let a = [0xAAu8; 64];
    let b = [0xAAu8; 64];
    let mut c = [0xAAu8; 64];
    c[63] ^= 1;

    assert!(constant_time_eq(&a, &b));
    assert!(!constant_time_eq(&a, &c));
}
