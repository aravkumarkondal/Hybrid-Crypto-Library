use criterion::{black_box, criterion_group, criterion_main, Criterion};
use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session};

fn bench_session_setup(c: &mut Criterion) {
    let alice_id = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_id = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_id, &[0x33; 32]).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);
    
    let bob_bundle = PreKeyBundle {
        identity_key: bob_id.public_key(),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };

    c.bench_function("session setup initiator", |b| b.iter(|| {
        Session::setup_as_initiator(
            black_box(&alice_id), black_box(&bob_bundle), &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
        ).unwrap()
    }));
}

criterion_group!(benches, bench_session_setup);
criterion_main!(benches);
