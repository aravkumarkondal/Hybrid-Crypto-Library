use std::arch::aarch64::*;
#[target_feature(enable = "neon")]
unsafe fn compute_d(h: uint64x2_t) -> uint64x2_t {
    vextq_u64(h, h, 1)
}
