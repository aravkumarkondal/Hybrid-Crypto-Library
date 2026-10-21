#![no_main]
use libfuzzer_sys::fuzz_target;
use e2ee::serialization::Serialize;
use e2ee::{IdentityPublicKey, Message};

fuzz_target!(|data: &[u8]| {
    let _ = IdentityPublicKey::deserialize(data);
    let _ = Message::deserialize(data);
});
