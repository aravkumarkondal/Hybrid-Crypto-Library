fn montgomery_reduce(a: i64) -> i32 {
    let u = (a as i32).wrapping_mul(4236238847u32 as i32);
    let mut t = (a - (u as i64 * 8380417i64)) >> 32;
    if t < 0 { t += 8380417i64; }
    t as i32
}
fn montgomery_reduce2(a: i64) -> i32 {
    let u = (a as i32).wrapping_mul(4236238847u32 as i32);
    let mut t = (a + (u as i64 * 8380417i64)) >> 32;
    if t < 0 { t += 8380417i64; }
    t as i32
}
fn main() {
    println!("red(1)   = {}", montgomery_reduce(1));
    println!("red2(1)  = {}", montgomery_reduce2(1));
    println!("expected = 8265825");
}
