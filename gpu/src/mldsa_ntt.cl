#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable

#define Q 8380417

// Barrett reduction for OpenCL
int barrett_reduce(int a) {
    int v = ((long)a * 8396807) >> 46;
    int res = a - v * Q;
    int mask_neg = res >> 31;
    res += mask_neg & Q;
    int mask_pos = (Q - 1 - res) >> 31;
    res -= mask_pos & Q;
    return res;
}

// Montgomery reduction
int montgomery_reduce(long a) {
    long u = (a * 4236238847UL) & 0xFFFFFFFF;
    int t = (a + u * Q) >> 32;
    int mask = t >> 31;
    t += mask & Q;
    return t;
}

// FQ Multiply
int fqmul(int a, int b) {
    return montgomery_reduce((long)a * b);
}

// OpenCL Kernel for batched NTT transforms
// Global size should be (num_polynomials, 128)
__attribute__((reqd_work_group_size(1, 128, 1)))
__kernel void ntt_batched(
    __global int *poly_array,
    __constant int *zetas
) {
    int poly_idx = get_global_id(0); // 0 to num_polys - 1
    int thread_id = get_global_id(1); // 0 to 127
    
    __global int *p = &poly_array[poly_idx * 256];
    
    // Normalize input
    int val = p[thread_id];
    int mask = val >> 31;
    p[thread_id] = val + (mask & 8380417);
    
    val = p[thread_id + 128];
    mask = val >> 31;
    p[thread_id + 128] = val + (mask & 8380417);
    
    barrier(CLK_GLOBAL_MEM_FENCE);

    
    int k = 1;
    for (int len = 128; len >= 1; len >>= 1) {
        int start = (thread_id / len) * (2 * len) + (thread_id % len);
        int zeta = zetas[k + (thread_id / len)];
        
        // Synchronize across polynomial thread block
        barrier(CLK_GLOBAL_MEM_FENCE);
        
        int t = fqmul(zeta, p[start + len]);
        p[start + len] = p[start] - t;
        p[start] = p[start] + t;
        
        if (p[start + len] < 0) p[start + len] += Q;
        if (p[start] >= Q) p[start] -= Q;
        
        k += (128 / len);
    }
}

// OpenCL Kernel for batched INTT transforms
__attribute__((reqd_work_group_size(1, 128, 1)))
__kernel void intt_batched(
    __global int *poly_array,
    __constant int *zetas
) {
    int poly_idx = get_global_id(0);
    int thread_id = get_global_id(1); // 0 to 127
    
    __global int *p = &poly_array[poly_idx * 256];
    
    // Normalize input
    int val = p[thread_id];
    int mask = val >> 31;
    p[thread_id] = val + (mask & 8380417);
    
    val = p[thread_id + 128];
    mask = val >> 31;
    p[thread_id + 128] = val + (mask & 8380417);
    
    barrier(CLK_GLOBAL_MEM_FENCE);

    
    int k = 255;
    for (int len = 1; len <= 128; len <<= 1) {
        int start = (thread_id / len) * (2 * len) + (thread_id % len);
        int zeta = zetas[k - (thread_id / len)]; // Constant-time inverse equivalent
        
        barrier(CLK_GLOBAL_MEM_FENCE);
        
        int t = p[start];
        p[start] = barrett_reduce(t + p[start + len]);
        p[start + len] = fqmul(zeta, p[start + len] - t);
        
        k -= (128 / len);
    }
    
    barrier(CLK_GLOBAL_MEM_FENCE);
    
    // Multiply by f = 256^-1 mod Q in Montgomery domain (16382)
    int f = 16382;
    p[thread_id] = fqmul(p[thread_id], f);
    p[thread_id + 128] = fqmul(p[thread_id + 128], f);
}
