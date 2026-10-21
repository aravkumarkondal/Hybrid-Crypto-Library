const Q: i32 = 8380417;

fn fqmul_ct(a: i32, b: i32) -> i32 {
    let p = a as i128 * b as i128;
    let v = (p * 2201172506692i128) >> 64;
    let mut c = (p - v * 8380417) as i32;
    
    let mask1 = c >> 31;
    c += mask1 & Q;
    
    let mask2 = (Q - 1 - c) >> 31;
    c -= mask2 & Q;
    
    let mask3 = c >> 31;
    c += mask3 & Q;
    
    c
}

fn fqmul_orig(a: i32, b: i32) -> i32 {
    let mut c = (a as i64 * b as i64) % (Q as i64);
    if c < 0 { c += Q as i64; }
    c as i32
}

fn main() {
    let mut fqmul_fails = 0;
    let max_a = Q;
    for a in -max_a..max_a {
        if a % 1000 == 0 {
            if fqmul_ct(a, a) != fqmul_orig(a, a) {
                println!("a={} res={} exp={}", a, fqmul_ct(a, a), fqmul_orig(a, a));
                fqmul_fails += 1;
                return;
            }
            if fqmul_ct(a, -a) != fqmul_orig(a, -a) {
                println!("a={} -a res={} exp={}", a, fqmul_ct(a, -a), fqmul_orig(a, -a));
                fqmul_fails += 1;
                return;
            }
        }
    }
    println!("Fqmul fails: {}", fqmul_fails);
}
