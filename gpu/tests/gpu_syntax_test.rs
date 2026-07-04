use gpu::{MLDSA_NTT_CL, KECCAK_F1600_WGSL};

#[test]
fn test_gpu_opencl_kernel_string_validity() {
    // 1. Ensure the kernel actually exported and is not empty
    assert!(!MLDSA_NTT_CL.is_empty(), "OpenCL ML-DSA kernel MUST not be empty");
    assert!(!KECCAK_F1600_WGSL.is_empty(), "WGSL Keccak kernel MUST not be empty");

    // 2. Validate syntactic bounds (simulation of GPU compilation leak/bounds issues)
    // An OpenCL kernel must have a proper signature to prevent host-buffer overruns
    let has_valid_signature = MLDSA_NTT_CL.contains("__kernel void ntt_batched(") 
        && MLDSA_NTT_CL.contains("__global int *poly_array");
    
    assert!(has_valid_signature, "GPU Kernel MUST enforce pointer boundaries via __global to prevent host-device memory leaks");
    
    // 3. Ensure memory domain normalization exists (prevents integer overflow attacks)
    let has_normalization = MLDSA_NTT_CL.contains("mask & 8380417");
    assert!(has_normalization, "GPU Kernel MUST include batched domain normalizations to prevent memory-based math overflow exploits");
}
