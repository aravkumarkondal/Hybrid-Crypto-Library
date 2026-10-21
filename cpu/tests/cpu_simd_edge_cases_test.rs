use cpu::ml_dsa_simd::{barrett_reduce, poly_add_simd, poly_sub_simd};

const Q: i32 = 8_380_417;

#[test]
fn test_barrett_reduce_boundary_values() {
    // Exact zero
    assert_eq!(barrett_reduce(0), 0);

    // Exact modulus Q -> should reduce to 0
    assert_eq!(barrett_reduce(Q), 0);

    // Q - 1 -> should remain Q - 1
    assert_eq!(barrett_reduce(Q - 1), Q - 1);

    // Q + 1 -> should reduce to 1
    assert_eq!(barrett_reduce(Q + 1), 1);

    // 2 * Q -> should reduce to 0
    assert_eq!(barrett_reduce(2 * Q), 0);

    // 2 * Q - 1 -> should reduce to Q - 1
    assert_eq!(barrett_reduce(2 * Q - 1), Q - 1);

    // Negative boundary: -1 -> should reduce to Q - 1
    assert_eq!(barrett_reduce(-1), Q - 1);

    // -Q -> should reduce to 0
    assert_eq!(barrett_reduce(-Q), 0);

    // -(Q - 1) -> should reduce to 1
    assert_eq!(barrett_reduce(-(Q - 1)), 1);

    // -2 * Q -> should reduce to 0
    assert_eq!(barrett_reduce(-2 * Q), 0);
}

#[test]
fn test_simd_poly_add_edge_cases() {
    let mut a = [Q - 1; 256];
    let b = [1; 256];
    // (Q - 1) + 1 = Q = 0 mod Q
    poly_add_simd(&mut a, &b);
    for (i, &val) in a.iter().enumerate() {
        assert_eq!(val, 0, "Index {} failed modular addition (Q-1) + 1", i);
    }

    // Maximal residue addition: (Q - 1) + (Q - 1) = 2Q - 2 = Q - 2 mod Q
    let mut max_a = [Q - 1; 256];
    let max_b = [Q - 1; 256];
    poly_add_simd(&mut max_a, &max_b);
    for (i, &val) in max_a.iter().enumerate() {
        assert_eq!(val, Q - 2, "Index {} failed addition (Q-1) + (Q-1)", i);
    }

    // Zero addition identity: X + 0 = X
    let mut orig = [0i32; 256];
    for i in 0..256 {
        orig[i] = (i as i32 * 31337) % Q;
    }
    let zero = [0i32; 256];
    let mut test_poly = orig;
    poly_add_simd(&mut test_poly, &zero);
    assert_eq!(test_poly, orig);
}

#[test]
fn test_simd_poly_sub_edge_cases() {
    // 0 - 1 = -1 = Q - 1 mod Q
    let mut a = [0; 256];
    let b = [1; 256];
    poly_sub_simd(&mut a, &b);
    for (i, &val) in a.iter().enumerate() {
        assert_eq!(val, Q - 1, "Index {} failed subtraction 0 - 1", i);
    }

    // Self-subtraction: X - X = 0
    let mut x = [0i32; 256];
    for i in 0..256 {
        x[i] = (i as i32 * 4242) % Q;
    }
    let copy = x;
    poly_sub_simd(&mut x, &copy);
    for (i, &val) in x.iter().enumerate() {
        assert_eq!(val, 0, "Index {} failed self-subtraction", i);
    }

    // Subtraction from zero of (Q - 1): 0 - (Q - 1) = 1 mod Q
    let mut z = [0; 256];
    let q_minus_1 = [Q - 1; 256];
    poly_sub_simd(&mut z, &q_minus_1);
    for (i, &val) in z.iter().enumerate() {
        assert_eq!(val, 1, "Index {} failed 0 - (Q - 1)", i);
    }
}

#[test]
fn test_simd_inverse_operations_roundtrip() {
    // Verify that (A + B) - B == A mod Q for all 256 elements
    let mut a = [0i32; 256];
    let mut b = [0i32; 256];
    for i in 0..256 {
        a[i] = (i as i32 * 12345) % Q;
        b[i] = (i as i32 * 67890) % Q;
    }

    let original_a = a;
    poly_add_simd(&mut a, &b);
    poly_sub_simd(&mut a, &b);

    assert_eq!(a, original_a, "Roundtrip (A + B) - B must equal A exactly across all SIMD lanes");
}
