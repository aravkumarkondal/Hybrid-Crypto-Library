fn fqmul(a: i16, b: i16) -> i16 {
    let p = a as i32 * b as i32;
    let v = ((p as i64 * 20159) >> 26) as i32;
    let mut res = p - v * 3329;
    
    let mask_neg = res >> 31;
    res += mask_neg & 3329;
    
    let mask_pos = (3328 - res) >> 31;
    res -= mask_pos & 3329;
    
    res as i16
}

fn barrett_reduce(a: i16) -> i16 {
    let p = a as i32;
    let v = (p * 20159) >> 26;
    let mut res = p - v * 3329;
    
    let mask_neg = res >> 31;
    res += mask_neg & 3329;
    
    let mask_pos = (3328 - res) >> 31;
    res -= mask_pos & 3329;
    
    res as i16
}

fn main() {
    let mut fails = 0;
    for a in -3329..=3329 {
        for b in -3329..=3329 {
            let res = fqmul(a, b);
            let mut expected = (a as i32 * b as i32) % 3329;
            if expected < 0 {
                expected += 3329;
            }
            if res as i32 != expected {
                fails += 1;
            }
        }
    }
    println!("fqmul fails: {}", fails);
    
    let mut b_fails = 0;
    for a in -32768..=32767 {
        let res = barrett_reduce(a);
        let mut expected = (a as i32) % 3329;
        if expected < 0 {
            expected += 3329;
        }
        if res as i32 != expected {
            b_fails += 1;
        }
    }
    println!("barrett fails: {}", b_fails);
}
