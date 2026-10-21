extern crate alloc;
use alloc::vec::Vec;
use e2ee::contact_discovery::{DiscoveryClient, DiscoveryEnclave};
use e2ee::session::Session;
use e2ee::identity::IdentityKeyPair;
use e2ee::prekeys::PreKeyBundle;

fn setup_sessions() -> (Session, Session) {
    let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let bob_identity = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let bob_spk = futures::executor::block_on(e2ee::prekeys::SignedPreKeyPair::generate(1, &[5; 32], &[6; 64], &bob_identity, &[7; 32])).unwrap();
    let bob_opk = e2ee::prekeys::OneTimePreKeyPair::generate(1, &[7; 32], &[8; 64]);

    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_identity.public_key()),
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public.clone(),
        signed_prekey_signature: bob_spk.signature.clone(),
        signed_prekey_id: bob_spk.id,
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public.clone()),
        one_time_prekey_id: Some(bob_opk.id),
    };

    let (alice_session, prekey_msg, _init_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_identity,
        &bob_bundle,
        &[10; 32],
        &[11; 32],
        Some(&[12; 32]),
        &[13; 32],
        &[14; 64],
        &[15; 32],
    )).unwrap();

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(
        &bob_identity,
        &bob_spk,
        Some(&bob_opk),
        &prekey_msg,
    )).unwrap();

    // Bob must receive the initial message to sync ratchets
    bob_session.receive_initial_message(
        &_init_msg,
        &[16; 32],
        &[17; 64],
        &[18; 32],
    ).unwrap();

    (alice_session, bob_session)
}

#[test]
fn test_private_contact_discovery_flow() {
    let (mut client_session, mut enclave_session) = setup_sessions();

    let mut registered_hashes = Vec::new();
    let hash_alice = [1u8; 32];
    let hash_bob = [2u8; 32];
    let hash_charlie = [3u8; 32];
    
    registered_hashes.push(hash_alice);
    registered_hashes.push(hash_charlie);
    
    let enclave = DiscoveryEnclave::new(registered_hashes);
    
    let contacts = &[&hash_bob, &hash_charlie, &[99u8; 32]];
    
    let request_msg = DiscoveryClient::prepare_request(&mut client_session, contacts).unwrap();
    
    let response_msg = enclave.process_request(
        &mut enclave_session,
        &request_msg,
        &[100; 32],
        &[101; 64],
        &[102; 32]
    ).unwrap();
    
    let matches = DiscoveryClient::process_response(
        &mut client_session,
        &response_msg,
        &[200; 32],
        &[201; 64],
        &[202; 32]
    ).unwrap();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0], hash_charlie);
}
