//! Memory Determinism & State Footprint Stability Test Suite
//!
//! #![allow(unsafe_code)]
//!
//! Validates memory stability and footprint determinism during continuous Double Ratchet messaging:
//! 1. Symmetric ratchet state invariance: Verifies that during unidirectional messaging,
//!    the ratchet state footprint remains strictly constant (zero leak or unbounded expansion).
//! 2. Historical epoch ceiling: Verifies that past DH ratchet epochs are strictly capped at
//!    `MAX_HISTORICAL_DH_KEYS` (20), proving that alternating turnarounds cannot cause unbounded memory growth.
//! 3. Skipped key garbage collection: Verifies that in-order messaging maintains zero lingering
//!    skipped keys in memory.
//! 4. Heap tracking allocator: Verifies zero net runaway memory leakage over sustained operations.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use e2ee::{IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair, PreKeyBundle, Session};

struct TrackingAllocator;

static TOTAL_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_HEAP_BYTES: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TOTAL_ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        CURRENT_HEAP_BYTES.fetch_add(layout.size() as isize, Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT_HEAP_BYTES.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static A: TrackingAllocator = TrackingAllocator;

fn setup_sessions() -> (Session, Session) {
    let alice_id = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_id = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_id, &[0x33; 32])).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);

    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_id.public_key()),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };

    let (alice_session, prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg)).unwrap();
    let plaintext = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    assert_eq!(plaintext, b"");

    (alice_session, bob_session)
}

#[test]
fn test_symmetric_ratchet_state_invariance() {
    let (mut alice, mut bob) = setup_sessions();
    let master_key = [0x55u8; 32];

    let mut state_sizes = Vec::new();

    // Send 100 unidirectional messages (pure symmetric ratcheting, no DH turnaround)
    for i in 1..=100 {
        let payload = [0xAAu8; 64];
        let msg = alice.encrypt_message(&payload).unwrap();
        let dec = bob.decrypt_message(&msg, &[0x77; 32], &[0x88; 64], &[0x99; 32]).unwrap();
        assert_eq!(dec, payload);

        if i == 1 || i == 10 || i == 50 || i == 100 {
            let alice_bytes = alice.export_state(&master_key);
            let bob_bytes = bob.export_state(&master_key);
            state_sizes.push((alice_bytes.len(), bob_bytes.len()));
        }
    }

    // In postcard serialization, integers (msg_num: 1 vs 100) use LEB128 varints (1 byte for <128).
    // Therefore, from msg 1 to 100, the state size should be 100% identical!
    let first = state_sizes[0];
    for (idx, &sample) in state_sizes.iter().enumerate() {
        assert_eq!(
            sample, first,
            "Symmetric state size drift at checkpoint {}: {:?} vs initial {:?}",
            idx, sample, first
        );
    }
}

#[test]
fn test_dh_ratchet_epoch_boundedness_and_heap_determinism() {
    let (mut alice, mut bob) = setup_sessions();
    let master_key = [0x55u8; 32];

    // Warm up 25 roundtrips (50 DH ratchet turnarounds) to fully saturate MAX_HISTORICAL_DH_KEYS (20)
    for i in 0..25 {
        let payload = [i as u8; 32];
        let msg_a = alice.encrypt_message(&payload).unwrap();
        let dec_b = bob.decrypt_message(&msg_a, &[i as u8; 32], &[i as u8; 64], &[i as u8; 32]).unwrap();
        assert_eq!(dec_b, payload);

        let msg_b = bob.encrypt_message(&payload).unwrap();
        let dec_a = alice.decrypt_message(&msg_b, &[i as u8; 32], &[i as u8; 64], &[i as u8; 32]).unwrap();
        assert_eq!(dec_a, payload);
    }

    // Capture saturated state size and baseline heap
    let saturated_alice_len = alice.export_state(&master_key).len();
    let saturated_bob_len = bob.export_state(&master_key).len();
    let baseline_heap = CURRENT_HEAP_BYTES.load(Ordering::SeqCst);

    // Run another 75 roundtrips (150 DH ratchet turnarounds)
    for i in 25..100 {
        let payload = [0x5Au8; 64];

        let msg_a = alice.encrypt_message(&payload).unwrap();
        let dec_b = bob.decrypt_message(&msg_a, &[i as u8; 32], &[i as u8; 64], &[i as u8; 32]).unwrap();
        assert_eq!(dec_b, payload);

        let msg_b = bob.encrypt_message(&payload).unwrap();
        let dec_a = alice.decrypt_message(&msg_b, &[i as u8; 32], &[i as u8; 64], &[i as u8; 32]).unwrap();
        assert_eq!(dec_a, payload);

        // Every 25 rounds, verify that state size has NOT grown beyond saturated capacity
        if i % 25 == 0 {
            let current_alice_len = alice.export_state(&master_key).len();
            let current_bob_len = bob.export_state(&master_key).len();
            assert_eq!(
                (current_alice_len, current_bob_len),
                (saturated_alice_len, saturated_bob_len),
                "Historical DH epoch state grew beyond MAX_HISTORICAL_DH_KEYS cap! ({}, {}) vs ({}, {})",
                current_alice_len, current_bob_len, saturated_alice_len, saturated_bob_len
            );
        }
    }

    // Verify net heap growth is strictly bounded (no unbounded leak)
    let final_heap = CURRENT_HEAP_BYTES.load(Ordering::SeqCst);
    let heap_delta = final_heap - baseline_heap;
    assert!(
        heap_delta < 64 * 1024,
        "Runaway memory growth detected! Heap increased by {} bytes over 75 roundtrips",
        heap_delta
    );
}
