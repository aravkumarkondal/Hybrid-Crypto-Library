fn montgomery_reduce(a: i64) -> i32 {
    let Q: i64 = 8380417;
    let u = (a as i32).wrapping_mul(4236238847u32 as i32);
    let mut t = (a + (u as i64 * Q)) >> 32;
    let mask = t >> 63;
    t += mask & Q;
    t as i32
}

fn main() {
    println!("{}", montgomery_reduce(1));
}
