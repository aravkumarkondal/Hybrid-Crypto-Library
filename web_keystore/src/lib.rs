#![cfg(target_arch = "wasm32")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;
use e2ee::keystore::{SecureKeyStore, BoxFuture};
use e2ee::errors::E2EError;
use e2ee::identity::{SoftwareIdentityKeyPair, IdentityPublicKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
export async function js_generate_and_seal(key_id, raw_bytes) {
    const aesKey = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({name: "AES-GCM", iv}, aesKey, raw_bytes);
    raw_bytes.fill(0);
    
    return new Promise((resolve, reject) => {
        const req = indexedDB.open("e2ee_keystore", 1);
        req.onupgradeneeded = e => e.target.result.createObjectStore("keys");
        req.onsuccess = e => {
            const db = e.target.result;
            const tx = db.transaction("keys", "readwrite");
            const store = tx.objectStore("keys");
            store.put({ aesKey, iv, ciphertext }, key_id);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        };
        req.onerror = () => reject();
    });
}

export async function js_unseal(key_id, out_buffer) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open("e2ee_keystore", 1);
        req.onupgradeneeded = e => e.target.result.createObjectStore("keys");
        req.onsuccess = e => {
            const db = e.target.result;
            const tx = db.transaction("keys", "readonly");
            const store = tx.objectStore("keys");
            const getReq = store.get(key_id);
            getReq.onsuccess = async () => {
                const data = getReq.result;
                if (!data) return reject("Not found");
                try {
                    const raw = await crypto.subtle.decrypt({name: "AES-GCM", iv: data.iv}, data.aesKey, data.ciphertext);
                    const view = new Uint8Array(raw);
                    out_buffer.set(view);
                    const len = view.length;
                    view.fill(0); // Zeroize the ArrayBuffer returned by subtle.decrypt
                    resolve(len);
                } catch(err) { reject(err); }
            };
            getReq.onerror = () => reject(getReq.error);
        };
        req.onerror = () => reject();
    });
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn js_generate_and_seal(key_id: &str, raw_bytes: &js_sys::Uint8Array) -> Result<(), JsValue>;
    
    #[wasm_bindgen(catch)]
    async fn js_unseal(key_id: &str, out_buffer: &js_sys::Uint8Array) -> Result<JsValue, JsValue>;
}

pub struct WebCryptoStore {
    indexeddb_key: String,
    ecc_public: [u8; 32],
    pqc_public: Vec<u8>,
}

impl WebCryptoStore {
    pub fn new(indexeddb_key: &str, ecc_public: [u8; 32], pqc_public: Vec<u8>) -> Self {
        Self {
            indexeddb_key: indexeddb_key.into(),
            ecc_public,
            pqc_public,
        }
    }

    pub async fn generate_and_seal(
        indexeddb_key: &str,
        entropy_ecc: &[u8; 32],
        entropy_pqc: &[u8; 32]
    ) -> Result<Self, E2EError> {
        let sw_key = SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc);
        
        let mut blob = Vec::with_capacity(32 + sw_key.pqc_private.len());
        blob.extend_from_slice(&sw_key.ecc_private);
        blob.extend_from_slice(sw_key.pqc_private.as_slice());

        let uint8_arr = js_sys::Uint8Array::from(blob.as_slice());
        
        js_generate_and_seal(indexeddb_key, &uint8_arr)
            .await
            .map_err(|_| E2EError::EncryptionError)?;
        
        hybrid_crypto::utils::zeroize(&mut blob);

        Ok(Self::new(indexeddb_key, sw_key.ecc_public, sw_key.pqc_public.clone()))
    }

    async fn unseal_software_key(&self) -> Result<SoftwareIdentityKeyPair, E2EError> {
        let mut blob = alloc::vec![0u8; 10000]; // Preallocate large enough buffer (ML-DSA-87 private key is 4896 bytes + 32)
        let out_buffer = js_sys::Uint8Array::from(blob.as_slice());
        
        let js_val = js_unseal(&self.indexeddb_key, &out_buffer).await.map_err(|_| E2EError::InvalidSignature)?;
        let len = js_val.as_f64().unwrap_or(0.0) as usize;
        
        if len != 32 + 4896 {
            hybrid_crypto::utils::zeroize(&mut blob);
            return Err(E2EError::InvalidSignature);
        }
        
        out_buffer.copy_to(&mut blob); // Copy from WASM memory view back to our vector
        
        let mut ecc_private = [0u8; 32];
        ecc_private.copy_from_slice(&blob[0..32]);
        
        let mut pqc_private_vec = alloc::vec![0u8; len - 32];
        pqc_private_vec.copy_from_slice(&blob[32..len]);
        let pqc_private = hybrid_crypto::utils::SecretKey(pqc_private_vec);
        
        hybrid_crypto::utils::zeroize(&mut blob);
        
        Ok(SoftwareIdentityKeyPair {
            ecc_private,
            ecc_public: self.ecc_public,
            pqc_private,
            pqc_public: self.pqc_public.clone(),
        })
    }
}

impl SecureKeyStore for WebCryptoStore {
    fn public_key(&self) -> BoxFuture<'_, Result<IdentityPublicKey, E2EError>> {
        Box::pin(async move {
            Ok(IdentityPublicKey {
                ecc_public: self.ecc_public,
                pqc_public: self.pqc_public.clone(),
            })
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> BoxFuture<'_, Result<Vec<u8>, E2EError>> {
        let data = data.to_vec();
        let rnd = *rnd;
        Box::pin(async move {
            let sw_key = self.unseal_software_key().await?;
            hybrid_crypto::ml_dsa::ml_dsa_87_sign(&sw_key.pqc_private, &data, &[], &rnd)
                .map_err(|_| E2EError::SigningError)
        })
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> BoxFuture<'_, Result<[u8; 32], E2EError>> {
        let peer_public = *peer_public;
        Box::pin(async move {
            let sw_key = self.unseal_software_key().await?;
            hybrid_crypto::x25519::x25519(&sw_key.ecc_private, &peer_public)
                .map_err(|_| E2EError::InvalidPreKeyBundle)
        })
    }
}
