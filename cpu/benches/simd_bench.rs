use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn math_operation_scalar(input: &[u32]) -> Vec<u32> {
    input.iter().map(|&x| x.wrapping_mul(3).wrapping_add(7)).collect()
}

fn math_operation_simd(input: &[u32]) -> Vec<u32> {
    // Mock SIMD processing
    input.iter().map(|&x| x.wrapping_mul(3).wrapping_add(7)).collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD vs Scalar CPU Performance");
    let data = vec![0x42424242u32; 1024];

    group.bench_function("Scalar", |b| b.iter(|| math_operation_scalar(black_box(&data))));
    group.bench_function("SIMD (AVX2/NEON)", |b| b.iter(|| math_operation_simd(black_box(&data))));
    
    group.finish();
}

// In a standard Criterion setup, this macro initializes the test runner.
// We configure it so the benchmarks can run when `cargo bench` is invoked.
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
