extern crate alloc;

use e2ee::animated_qr::{encode_animated_qr, QrAssembler, QrFrame};
use e2ee::errors::E2EError;

#[test]
fn test_qr_encode_and_reassemble() {
    let payload = b"This is a large payload that will be split into multiple animated QR frames for testing.";
    let chunk_size = 10;
    
    let frames = encode_animated_qr(payload, chunk_size);
    assert!(frames.len() > 1);

    let mut assembler = QrAssembler::new();
    let mut result = None;
    
    // Process frames in order
    for frame in frames.iter() {
        let serialized = frame.serialize();
        let decoded_frame = QrFrame::deserialize(&serialized).unwrap();
        result = assembler.add_frame(decoded_frame).unwrap();
    }
    
    assert!(result.is_some());
    assert_eq!(result.unwrap(), payload);
}

#[test]
fn test_qr_out_of_order_and_duplicates() {
    let payload = b"Out of order and duplicate testing string payload.";
    let frames = encode_animated_qr(payload, 5);
    
    let mut assembler = QrAssembler::new();
    
    // Add frames out of order and with duplicates
    assert!(assembler.add_frame(frames[2].clone()).unwrap().is_none());
    assert!(assembler.add_frame(frames[0].clone()).unwrap().is_none());
    assert!(assembler.add_frame(frames[2].clone()).unwrap().is_none()); // Duplicate
    
    let mut final_res = None;
    for i in 0..frames.len() {
        if i != 0 && i != 2 {
            if let Ok(Some(data)) = assembler.add_frame(frames[i].clone()) {
                final_res = Some(data);
            }
        }
    }
    
    // Make sure we have all frames now. Let's just loop again and add all to verify duplicate handling doesn't break it.
    for frame in frames {
        let _ = assembler.add_frame(frame);
    }
    
    assert!(final_res.is_some());
    assert_eq!(final_res.unwrap(), payload);
}

#[test]
fn test_qr_corruption_and_injection() {
    let payload = b"Fuzz target base payload";
    let frames = encode_animated_qr(payload, 8);
    
    // Corrupt a chunk's data in the serialized form to test deserialize hash verification
    let mut serialized = frames[1].serialize();
    let last_byte = serialized.len() - 1;
    serialized[last_byte] ^= 1; // Flip a bit
    
    assert!(matches!(QrFrame::deserialize(&serialized), Err(E2EError::InvalidMessageFormat)));
    
    // Test injection of a valid frame from a different payload
    let other_payload = b"Malicious payload injection attempt";
    let other_frames = encode_animated_qr(other_payload, 8);
    
    let mut assembler = QrAssembler::new();
    assembler.add_frame(frames[0].clone()).unwrap(); // Init with valid payload
    
    // Try to inject frame from other payload (even if sequence number matches)
    let err = assembler.add_frame(other_frames[1].clone()).unwrap_err();
    assert!(matches!(err, E2EError::InvalidMessageFormat));
}
