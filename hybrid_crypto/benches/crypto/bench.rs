use criterion::{criterion_group, criterion_main, Criterion};
use hybrid_crypto::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};

fn bench_ml_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768");
    let seed = [0u8; 64];
    
    group.bench_function("keygen", |b| {
        b.iter(|| ml_kem_768_keypair(&seed))
    });

    let (pk, sk) = ml_kem_768_keypair(&seed);
    let enc_seed = [1u8; 32];
    
    group.bench_function("encapsulate", |b| {
        b.iter(|| ml_kem_768_encapsulate(&pk, &enc_seed).unwrap())
    });

    let (ct, _) = ml_kem_768_encapsulate(&pk, &enc_seed).unwrap();
    group.bench_function("decapsulate", |b| {
        b.iter(|| ml_kem_768_decapsulate(&sk, &ct))
    });
    group.finish();
}

fn bench_ml_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-87");
    let seed = [0u8; 32];
    
    group.bench_function("keygen", |b| {
        b.iter(|| ml_dsa_87_keypair(&seed))
    });

    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"benchmark message";
    let rnd = [2u8; 32];
    
    group.bench_function("sign", |b| {
        b.iter(|| ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap())
    });

    let sig = ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| ml_dsa_87_verify(&pk, msg, &[], &sig))
    });
    group.finish();
}

criterion_group!(benches, bench_ml_kem, bench_ml_dsa);
criterion_main!(benches);
