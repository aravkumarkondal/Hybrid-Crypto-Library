use std::arch::aarch64::*;
#[target_feature(enable = "neon")]
unsafe fn reverse_bytes(a: &[u8; 16]) -> [u8; 16] {
    let va = vld1q_u8(a.as_ptr());
    let rev64 = vrev64q_u8(va);
    let rev128 = vextq_u8(rev64, rev64, 8);
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), rev128);
    out
}
fn main() {
    let mut a = [0u8; 16];
    for i in 0..16 { a[i] = i as u8; }
    let rev = unsafe { reverse_bytes(&a) };
    println!("{:?}", rev);
}
