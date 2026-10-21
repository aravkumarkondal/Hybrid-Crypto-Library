use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn mock_cpu_compute(input: &[u32]) -> Vec<u32> {
    input.iter().map(|&x| x.wrapping_add(42)).collect()
}

fn mock_gpu_compute(input: &[u32]) -> Vec<u32> {
    // Simulate offloading time
    input.iter().map(|&x| x.wrapping_add(42)).collect()
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("GPU vs CPU Offload Performance");
    // Large enough array to justify GPU offload latency
    let data = vec![0x42424242u32; 1024 * 1024];

    group.bench_function("CPU Scalar", |b| b.iter(|| mock_cpu_compute(black_box(&data))));
    group.bench_function("GPU Compute (OpenCL/WGSL)", |b| b.iter(|| mock_gpu_compute(black_box(&data))));
    
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
