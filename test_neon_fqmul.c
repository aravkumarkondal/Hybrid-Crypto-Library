#include <arm_neon.h>
#include <stdio.h>

#define Q 8380417

int32x4_t fqmul_neon(int32x4_t a, int32_t b) {
    int32x4_t b_vec = vdupq_n_s32(b);
    int32x4_t qinv = vdupq_n_s32((int32_t)4236238847u);
    int32x4_t q = vdupq_n_s32(Q);
    
    int32x4_t a_low = vmulq_s32(a, b_vec);
    int32x4_t u = vmulq_s32(a_low, qinv);
    
    int32x2_t a_low_half = vget_low_s32(a);
    int32x2_t a_high_half = vget_high_s32(a);
    int32x2_t b_low_half = vget_low_s32(b_vec);
    int32x2_t b_high_half = vget_high_s32(b_vec);
    
    int32x2_t u_low_half = vget_low_s32(u);
    int32x2_t u_high_half = vget_high_s32(u);
    int32x2_t q_low_half = vget_low_s32(q);
    int32x2_t q_high_half = vget_high_s32(q);
    
    int64x2_t a_mul_low = vmull_s32(a_low_half, b_low_half);
    int64x2_t a_mul_high = vmull_s32(a_high_half, b_high_half);
    
    int64x2_t u_mul_low = vmull_s32(u_low_half, q_low_half);
    int64x2_t u_mul_high = vmull_s32(u_high_half, q_high_half);
    
    int64x2_t sum_low = vaddq_s64(a_mul_low, u_mul_low);
    int64x2_t sum_high = vaddq_s64(a_mul_high, u_mul_high);
    
    int32x2_t res_low = vshrn_n_s64(sum_low, 32);
    int32x2_t res_high = vshrn_n_s64(sum_high, 32);
    
    int32x4_t res = vcombine_s32(res_low, res_high);
    
    int32x4_t zero = vdupq_n_s32(0);
    uint32x4_t cmp = vcltq_s32(res, zero);
    int32x4_t add_q = vandq_s32(vreinterpretq_s32_u32(cmp), q);
    
    return vaddq_s32(res, add_q);
}

int32_t montgomery_reduce(int64_t a) {
    int64_t u = (int64_t)(int32_t)(a * 4236238847u);
    int32_t t = (int32_t)((a + u * Q) >> 32);
    if (t < 0) t += Q;
    return t;
}

int main() {
    int32_t a_arr[4] = {1234567, -2345678, 3456789, -4567890};
    int32_t b = 5678901;
    
    int32x4_t a = vld1q_s32(a_arr);
    int32x4_t res = fqmul_neon(a, b);
    
    int32_t res_arr[4];
    vst1q_s32(res_arr, res);
    
    for (int i=0; i<4; i++) {
        int32_t expected = montgomery_reduce((int64_t)a_arr[i] * b);
        if (res_arr[i] != expected) {
            printf("Mismatch at %d: %d != %d\n", i, res_arr[i], expected);
            return 1;
        }
    }
    printf("Success!\n");
    return 0;
}
