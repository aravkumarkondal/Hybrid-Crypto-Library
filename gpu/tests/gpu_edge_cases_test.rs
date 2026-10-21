use gpu::{MLDSA_NTT_CL, KECCAK_F1600_WGSL};

const Q: i32 = 8_380_417;

#[test]
fn test_opencl_kernel_no_data_dependent_branches() {
    // Audit OpenCL kernel to verify absence of secret-dependent if conditions
    // In ntt_batched, inner loops must use branchless masking rather than `if (p[...] < 0)`
    assert!(
        !MLDSA_NTT_CL.contains("if (p[start + len] < 0)"),
        "OpenCL NTT kernel must NOT contain data-dependent branch on negative coefficients"
    );
    assert!(
        !MLDSA_NTT_CL.contains("if (p[start] >= Q)"),
        "OpenCL NTT kernel must NOT contain data-dependent branch on >= Q coefficients"
    );

    // Verify presence of branchless bitwise masks
    assert!(
        MLDSA_NTT_CL.contains("mask_neg = p[start + len] >> 31"),
        "OpenCL NTT kernel must employ constant-time sign-bit shift masking for negative values"
    );
    assert!(
        MLDSA_NTT_CL.contains("mask_pos = (Q - 1 - p[start]) >> 31"),
        "OpenCL NTT kernel must employ constant-time sign-bit shift masking for values >= Q"
    );
}

#[test]
fn test_opencl_kernel_synchronization_and_workgroup_bounds() {
    // Both batched kernels must enforce strict 128-thread workgroup layout
    assert!(MLDSA_NTT_CL.contains("__attribute__((reqd_work_group_size(1, 128, 1)))"));
    // Must contain global memory barrier
    assert!(MLDSA_NTT_CL.contains("barrier(CLK_GLOBAL_MEM_FENCE)"));
}

#[test]
fn test_wgsl_keccak_kernel_bounds_and_structure() {
    // WGSL Keccak kernel must validate num_states bounds
    assert!(KECCAK_F1600_WGSL.contains("if idx >= num_states { return; }"));
    // WGSL compute workgroup size must be fixed
    assert!(KECCAK_F1600_WGSL.contains("@workgroup_size(64)"));
    // State length must be 25 elements (array<vec2<u32>, 25>) representing 1600-bit state
    assert!(KECCAK_F1600_WGSL.contains("array<vec2<u32>, 25>"));
}

#[test]
fn test_gpu_opencl_butterfly_reduction_mathematical_equivalence() {
    // Emulate the OpenCL kernel's branchless bitwise reduction in Rust
    // and verify that for all edge-case inputs, it produces the exact same result
    // as canonical mathematical modular arithmetic in [0, Q).

    fn opencl_butterfly_reduce(mut p_sub: i32, mut p_add: i32) -> (i32, i32) {
        // As defined in mldsa_ntt.cl:
        // int mask_neg = p[start + len] >> 31;
        // p[start + len] += mask_neg & Q;
        let mask_neg = p_sub >> 31;
        p_sub += mask_neg & Q;

        // int mask_pos = (Q - 1 - p[start]) >> 31;
        // p[start] -= mask_pos & Q;
        let mask_pos = (Q - 1 - p_add) >> 31;
        p_add -= mask_pos & Q;

        (p_sub, p_add)
    }

    // Edge-case scenarios
    let edge_cases = [
        // (p_start, t)
        (0, 0),
        (0, 1),
        (0, Q - 1),
        (1, 0),
        (Q - 1, 0),
        (Q - 1, 1),
        (Q - 1, Q - 1),
        (Q / 2, Q / 2),
        (Q - 100, 200),
    ];

    for &(p_val, t) in &edge_cases {
        let raw_sub = p_val - t;
        let raw_add = p_val + t;

        let (reduced_sub, reduced_add) = opencl_butterfly_reduce(raw_sub, raw_add);

        // Expected mathematical values in [0, Q)
        let expected_sub = ((raw_sub % Q) + Q) % Q;
        let expected_add = raw_add % Q;

        assert_eq!(
            reduced_sub, expected_sub,
            "OpenCL bitwise subtraction reduction failed for p={}, t={}",
            p_val, t
        );
        assert_eq!(
            reduced_add, expected_add,
            "OpenCL bitwise addition reduction failed for p={}, t={}",
            p_val, t
        );
        assert!(reduced_sub >= 0 && reduced_sub < Q);
        assert!(reduced_add >= 0 && reduced_add < Q);
    }
}
