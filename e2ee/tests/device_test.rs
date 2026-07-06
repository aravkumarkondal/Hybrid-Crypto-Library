extern crate alloc;
use e2ee::{AccountIdentity, DeviceKeyPair, DeviceRegistration, DeviceList, IdentityKeyPair};

#[test]
fn test_device_certification_and_list() {
    // 1. Setup Alice's Account
    let account_keys = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let account = AccountIdentity::new(account_keys);
    let account_pub = account.root_key.public_key();

    // 2. Setup Alice's Phone
    let phone_keys = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let phone = DeviceKeyPair::new(1, phone_keys);

    // 3. Setup Alice's Laptop
    let laptop_keys = IdentityKeyPair::generate(&[5; 32], &[6; 32]);
    let laptop = DeviceKeyPair::new(2, laptop_keys);

    // 4. Certify devices
    let rnd1 = [9; 32];
    let phone_sig = account.certify_device(&phone.public_key(), &rnd1).expect("Failed to sign");
    
    let rnd2 = [10; 32];
    let laptop_sig = account.certify_device(&laptop.public_key(), &rnd2).expect("Failed to sign");

    let reg_phone = DeviceRegistration {
        device_id: phone.device_id,
        device_pub: phone.public_key(),
        signature: phone_sig,
    };

    let reg_laptop = DeviceRegistration {
        device_id: laptop.device_id,
        device_pub: laptop.public_key(),
        signature: laptop_sig,
    };

    // 5. Verify individual registrations
    assert!(reg_phone.verify(&account_pub));
    assert!(reg_laptop.verify(&account_pub));

    // 6. Create Device List Version 1 (just Phone)
    let mut v1 = DeviceList {
        account_pub: account_pub.clone(),
        version: 1,
        timestamp: 1600000000,
        active_devices: vec![reg_phone.clone()],
        signature: vec![],
    };

    let mut payload = alloc::vec::Vec::new();
    payload.extend_from_slice(b"DEVICE_LIST");
    payload.extend_from_slice(&v1.version.to_le_bytes());
    payload.extend_from_slice(&v1.timestamp.to_le_bytes());
    for dev in &v1.active_devices {
        payload.extend_from_slice(&dev.device_id.to_le_bytes());
        payload.extend_from_slice(&dev.device_pub.ecc_public);
        payload.extend_from_slice(&dev.device_pub.pqc_public);
        payload.extend_from_slice(&dev.signature.0);
    }
    
    let sig_v1 = account.root_key.sign(&payload, &rnd1).unwrap();
    v1.signature = sig_v1;

    assert!(v1.verify());

    // 7. Create Device List Version 2 (Phone + Laptop)
    let mut v2 = DeviceList {
        account_pub: account_pub.clone(),
        version: 2,
        timestamp: 1600001000,
        active_devices: vec![reg_phone, reg_laptop],
        signature: vec![],
    };

    let mut payload2 = alloc::vec::Vec::new();
    payload2.extend_from_slice(b"DEVICE_LIST");
    payload2.extend_from_slice(&v2.version.to_le_bytes());
    payload2.extend_from_slice(&v2.timestamp.to_le_bytes());
    for dev in &v2.active_devices {
        payload2.extend_from_slice(&dev.device_id.to_le_bytes());
        payload2.extend_from_slice(&dev.device_pub.ecc_public);
        payload2.extend_from_slice(&dev.device_pub.pqc_public);
        payload2.extend_from_slice(&dev.signature.0);
    }

    let sig_v2 = account.root_key.sign(&payload2, &rnd2).unwrap();
    v2.signature = sig_v2;

    assert!(v2.verify());
    
    // 8. Test Rollback Prevention
    assert!(v2.is_valid_update_from(&v1));
    assert!(!v1.is_valid_update_from(&v2)); // V1 is older than V2, should reject
}
