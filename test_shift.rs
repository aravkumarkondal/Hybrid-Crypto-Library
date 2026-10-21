fn main() {
    let p = -3328i32 * 3328i32;
    let v = ((p as i64 * 20159) >> 26) as i32;
    println!("v: {}", v);
}
