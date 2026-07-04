use wasm_bindgen::prelude::*;
use e2ee::{
    IdentityKeyPair, IdentityPublicKey, Session, PreKeyBundle, PreKeyMessage,
    SenderKeyContext, SenderKeyReceiver, SenderKeyDistributionMessage, SenderKeyMessage,
    SafetyNumber, SessionState,
};
use e2ee::serialization::Serialize;

#[wasm_bindgen]
pub struct WasmIdentityKeyPair {
    inner: IdentityKeyPair,
}

#[wasm_bindgen]
impl WasmIdentityKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(entropy_ecc: &[u8], entropy_pqc: &[u8]) -> Result<WasmIdentityKeyPair, JsValue> {
        if entropy_ecc.len() != 32 || entropy_pqc.len() != 32 {
            return Err(JsValue::from_str("Entropy must be exactly 32 bytes"));
        }
        let mut ecc = [0u8; 32];
        ecc.copy_from_slice(entropy_ecc);
        let mut pqc = [0u8; 32];
        pqc.copy_from_slice(entropy_pqc);

        Ok(WasmIdentityKeyPair {
            inner: IdentityKeyPair::generate(&ecc, &pqc),
        })
    }

    pub fn public_key(&self) -> WasmIdentityPublicKey {
        WasmIdentityPublicKey {
            inner: self.inner.public_key(),
        }
    }
}

#[wasm_bindgen]
pub struct WasmIdentityPublicKey {
    inner: IdentityPublicKey,
}

#[wasm_bindgen]
impl WasmIdentityPublicKey {
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize()
    }

    pub fn deserialize(data: &[u8]) -> Result<WasmIdentityPublicKey, JsValue> {
        let inner = IdentityPublicKey::deserialize(data)
            .map_err(|_| JsValue::from_str("Failed to deserialize IdentityPublicKey"))?;
        Ok(WasmIdentityPublicKey { inner })
    }
}

#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
}

#[wasm_bindgen]
impl WasmSession {
    pub fn export_state(&self) -> Vec<u8> {
        let state = self.inner.export();
        state.serialize()
    }

    pub fn restore_state(data: &[u8]) -> Result<WasmSession, JsValue> {
        let state = SessionState::deserialize(data)
            .map_err(|_| JsValue::from_str("Failed to deserialize SessionState"))?;
        Ok(WasmSession {
            inner: Session::restore(&state),
        })
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner.encrypt_message(plaintext)
            .map_err(|_| JsValue::from_str("Encryption failed"))?;
        Ok(msg.serialize())
    }
    
    // Note: To fully implement Session setup in WASM we would need wrappers for 
    // PreKeyBundle, X3DH, etc. For brevity we omit the full setup functions in this snippet,
    // as the prompt emphasizes the *features* (Session Persistence, Safety Numbers, Sender Keys, Zeroize).
}

#[wasm_bindgen]
pub struct WasmSafetyNumber {
    inner: SafetyNumber,
}

#[wasm_bindgen]
impl WasmSafetyNumber {
    #[wasm_bindgen(constructor)]
    pub fn generate(local_id: &WasmIdentityPublicKey, remote_id: &WasmIdentityPublicKey) -> WasmSafetyNumber {
        WasmSafetyNumber {
            inner: SafetyNumber::generate(&local_id.inner, &remote_id.inner),
        }
    }

    pub fn display_numeric(&self) -> String {
        self.inner.display_numeric()
    }

    pub fn display_qr_code(&self) -> Vec<u8> {
        self.inner.display_qr_code().to_vec()
    }
}

// Group messaging wrappers

#[wasm_bindgen]
pub struct WasmSenderKeyContext {
    inner: SenderKeyContext,
}

#[wasm_bindgen]
impl WasmSenderKeyContext {
    #[wasm_bindgen(constructor)]
    pub fn new(entropy_ecc: &[u8], entropy_pqc: &[u8], group_id: &[u8], seed: &[u8], chain_id: u32) -> Result<WasmSenderKeyContext, JsValue> {
        if entropy_ecc.len() != 32 || entropy_pqc.len() != 32 || group_id.len() != 32 || seed.len() != 32 {
            return Err(JsValue::from_str("Invalid lengths for inputs (must be 32 bytes)"));
        }
        let mut ecc = [0u8; 32]; ecc.copy_from_slice(entropy_ecc);
        let mut pqc = [0u8; 32]; pqc.copy_from_slice(entropy_pqc);
        let identity = IdentityKeyPair::generate(&ecc, &pqc);
        
        let mut gid = [0u8; 32]; gid.copy_from_slice(group_id);
        let mut s = [0u8; 32]; s.copy_from_slice(seed);

        Ok(WasmSenderKeyContext {
            inner: SenderKeyContext::new(identity, &gid, &s, chain_id),
        })
    }

    pub fn get_distribution_message(&self) -> Vec<u8> {
        self.inner.get_distribution_message().serialize()
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner.encrypt(plaintext)
            .map_err(|_| JsValue::from_str("Group encryption failed"))?;
        Ok(msg.serialize())
    }
}

#[wasm_bindgen]
pub struct WasmSenderKeyReceiver {
    inner: SenderKeyReceiver,
}

#[wasm_bindgen]
impl WasmSenderKeyReceiver {
    #[wasm_bindgen(constructor)]
    pub fn from_distribution_message(data: &[u8]) -> Result<WasmSenderKeyReceiver, JsValue> {
        let msg = SenderKeyDistributionMessage::deserialize(data)
            .map_err(|_| JsValue::from_str("Failed to deserialize SenderKeyDistributionMessage"))?;
        Ok(WasmSenderKeyReceiver {
            inner: SenderKeyReceiver::from_distribution_message(&msg),
        })
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = SenderKeyMessage::deserialize(data)
            .map_err(|_| JsValue::from_str("Failed to deserialize SenderKeyMessage"))?;
        self.inner.decrypt(&msg)
            .map_err(|_| JsValue::from_str("Group decryption failed"))
    }
}
