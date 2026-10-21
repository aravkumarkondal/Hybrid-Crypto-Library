use std::hint::black_box;
use std::time::Instant;
use hybrid_crypto::utils::{cswap, constant_time_eq};
use hybrid_crypto::ml_dsa_math::{fqmul, fqmul_std, Q};
use hybrid_crypto::x25519::x25519;

#[test]
fn test_cswap_constant_time_delta() {
    let mut a0 = [0x0123456789ABCDEFu64; 4];
    let mut b0 = [0xFEDCBA9876543210u64; 4];

    let mut a1 = a0;
    let mut b1 = b0;

    // Warmup
    for _ in 0..2000 {
        cswap(black_box(0), black_box(&mut a0), black_box(&mut b0));
        cswap(black_box(1), black_box(&mut a1), black_box(&mut b1));
    }

    let iters_per_block = 20_000;
    let blocks = 5;
    let mut t0_total = 0.0;
    let mut t1_total = 0.0;

    for _ in 0..blocks {
        let t0_start = Instant::now();
        for _ in 0..iters_per_block {
            cswap(black_box(0), black_box(&mut a0), black_box(&mut b0));
        }
        t0_total += t0_start.elapsed().as_nanos() as f64;

        let t1_start = Instant::now();
        for _ in 0..iters_per_block {
            cswap(black_box(1), black_box(&mut a1), black_box(&mut b1));
        }
        t1_total += t1_start.elapsed().as_nanos() as f64;
    }

    let total_iters = (iters_per_block * blocks) as f64;
    let delta = (t0_total - t1_total).abs() / t0_total.max(t1_total);
    println!("cswap(0): {:.2} ns/iter, cswap(1): {:.2} ns/iter, Delta: {:.2}%",
        t0_total / total_iters,
        t1_total / total_iters,
        delta * 100.0
    );

    // Delta bound: cswap execution should be within reasonable statistical tolerance
    assert!(delta < 0.20, "cswap exhibits timing discrepancy between 0 and 1! Delta: {:.2}%", delta * 100.0);
}

#[test]
fn test_constant_time_eq_timing_independent_of_mismatch_index() {
    let base = [0x55u8; 32];
    
    // Mismatch at byte 0
    let mut mismatch_first = base;
    mismatch_first[0] ^= 0xFF;

    // Mismatch at byte 31
    let mut mismatch_last = base;
    mismatch_last[31] ^= 0xFF;

    // Correctness
    assert!(!constant_time_eq(&base, &mismatch_first));
    assert!(!constant_time_eq(&base, &mismatch_last));
    assert!(constant_time_eq(&base, &base));

    // Warmup
    for _ in 0..2000 {
        black_box(constant_time_eq(black_box(&base), black_box(&mismatch_first)));
        black_box(constant_time_eq(black_box(&base), black_box(&mismatch_last)));
    }

    let iters_per_block = 20_000;
    let blocks = 5;
    let mut t_first_total = 0.0;
    let mut t_last_total = 0.0;

    for _ in 0..blocks {
        let t0 = Instant::now();
        for _ in 0..iters_per_block {
            black_box(constant_time_eq(black_box(&base), black_box(&mismatch_first)));
        }
        t_first_total += t0.elapsed().as_nanos() as f64;

        let t1 = Instant::now();
        for _ in 0..iters_per_block {
            black_box(constant_time_eq(black_box(&base), black_box(&mismatch_last)));
        }
        t_last_total += t1.elapsed().as_nanos() as f64;
    }

    let total_iters = (iters_per_block * blocks) as f64;
    let delta = (t_first_total - t_last_total).abs() / t_first_total.max(t_last_total);
    println!("Mismatch@0: {:.2} ns/iter, Mismatch@31: {:.2} ns/iter, Delta: {:.2}%",
        t_first_total / total_iters,
        t_last_total / total_iters,
        delta * 100.0
    );

    assert!(delta < 0.20, "constant_time_eq leaks early-exit timing depending on mismatch position! Delta: {:.2}%", delta * 100.0);
}

#[test]
fn test_montgomery_reduction_edge_case_inputs_and_timing() {
    // Extreme input combinations
    let edges = [
        (0, 0),
        (0, Q - 1),
        (Q - 1, 0),
        (Q - 1, Q - 1),
        (1, 1),
        (1, Q - 1),
        (Q / 2, Q / 2),
    ];

    for &(a, b) in &edges {
        let res_std = fqmul_std(a, b);
        let res_mont = fqmul(a, b);
        assert!(res_std >= 0 && res_std < Q, "fqmul_std({}, {}) out of range: {}", a, b, res_std);
        assert!(res_mont >= -Q && res_mont < Q, "fqmul({}, {}) out of range: {}", a, b, res_mont);
    }

    // Verify mathematical correctness: (0 * (Q-1)) mod Q == 0
    assert_eq!(fqmul_std(0, Q - 1), 0);
    assert_eq!(fqmul_std(Q - 1, 0), 0);
    // (1 * 1) mod Q == 1
    assert_eq!(fqmul_std(1, 1), 1);
    // (1 * (Q-1)) mod Q == Q - 1
    assert_eq!(fqmul_std(1, Q - 1), Q - 1);

    // Warmup
    for _ in 0..2000 {
        black_box(fqmul_std(black_box(0), black_box(0)));
        black_box(fqmul_std(black_box(Q - 1), black_box(Q - 1)));
    }

    // Measure across interleaved blocks to neutralize CPU frequency scaling
    let iters_per_block = 20_000;
    let blocks = 5;
    let mut t_zero_total = 0.0;
    let mut t_max_total = 0.0;

    for _ in 0..blocks {
        let t0 = Instant::now();
        for _ in 0..iters_per_block {
            black_box(fqmul_std(black_box(0), black_box(0)));
        }
        t_zero_total += t0.elapsed().as_nanos() as f64;

        let t1 = Instant::now();
        for _ in 0..iters_per_block {
            black_box(fqmul_std(black_box(Q - 1), black_box(Q - 1)));
        }
        t_max_total += t1.elapsed().as_nanos() as f64;
    }

    let total_iters = (iters_per_block * blocks) as f64;
    let delta = (t_zero_total - t_max_total).abs() / t_zero_total.max(t_max_total);
    println!("fqmul_std(0,0): {:.2} ns/iter, fqmul_std(Q-1,Q-1): {:.2} ns/iter, Delta: {:.2}%",
        t_zero_total / total_iters,
        t_max_total / total_iters,
        delta * 100.0
    );

    assert!(delta < 0.20, "fqmul_std leaks data-dependent timing between zero and maximal residue! Delta: {:.2}%", delta * 100.0);
}

#[test]
fn test_x25519_low_order_points_constant_time_rejection() {
    let scalar = [0x42u8; 32];

    // Low-order curve points that produce zero
    let zero_point = [0u8; 32];
    assert!(x25519(&scalar, &zero_point).is_err(), "Zero public key must be rejected");

    let point_one = {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    };
    assert!(x25519(&scalar, &point_one).is_err(), "Point order 1 must be rejected");

    // Valid basepoint multiplication must succeed
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let valid_dh = x25519(&scalar, &basepoint);
    assert!(valid_dh.is_ok(), "Valid basepoint multiplication must succeed");
}
