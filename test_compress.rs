fn compress_q(x: i16, d: usize) -> u16 {
    let mut x_u32 = (x % 3329) as i32;
    if x_u32 < 0 { x_u32 += 3329; }
    let x_u32 = x_u32 as u32;
    let a = x_u32 << d;
    let val = a * 2 + 3329;
    let res = ((val as u64 * 10321339) >> 36) as u16;
    res & ((1 << d) - 1)
}

fn ref_compress(x: i16, d: usize) -> u16 {
    let mut x_u32 = (x % 3329) as i32;
    if x_u32 < 0 { x_u32 += 3329; }
    let x_u32 = x_u32 as u64;
    let val = x_u32 * (1 << (d + 1)) + 3329;
    let res = (val / 6658) as u16;
    res & ((1 << d) - 1)
}

fn main() {
    let ds = [1, 4, 10, 11];
    let mut fail = false;
    for &d in &ds {
        for x in 0..3329 {
            if compress_q(x as i16, d) != ref_compress(x as i16, d) {
                println!("Fail for d={}, x={}: {} vs {}", d, x, compress_q(x, d), ref_compress(x, d));
                fail = true;
            }
        }
    }
    if !fail { println!("Compress is exactly correct!"); }
}
