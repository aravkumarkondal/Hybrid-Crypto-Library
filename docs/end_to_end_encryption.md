# Hybrid Post-Quantum End-To-End Encryption

This document outlines the architecture, threat model, and technical specifications of the Signal-inspired End-To-End Encryption (E2EE) module implemented in the `hybrid_crypto` repository.

## Architecture

The protocol is designed as a hybrid classical-post-quantum system. All operations that provide long-term confidentiality or authentication use a combination of a classical algorithm (X25519) and a post-quantum algorithm (ML-KEM or ML-DSA) to achieve **Post-Quantum Security** while retaining **Classical Security** as a fallback.

### Cryptographic Primitives
- **Classical Key Agreement**: X25519
- **Post-Quantum Key Encapsulation**: ML-KEM-768
- **Post-Quantum Digital Signatures**: ML-DSA-87
- **Key Derivation**: HKDF-SHA256
- **Symmetric Encryption**: AES-256-GCM

### Key Hierarchy
1. **Identity Key (`IdentityKeyPair`)**: Long-term identity combining an X25519 DH keypair and an ML-DSA-87 signature keypair.
2. **Signed PreKey (`SignedPreKeyPair`)**: Medium-term keys combining X25519 and ML-KEM-768, signed by the Identity Key's ML-DSA-87 private key to prevent tampering.
3. **One-Time PreKey (`OneTimePreKeyPair`)**: Ephemeral keys combining X25519 and ML-KEM-768 for asynchronous session establishment. Used once and discarded.

### Session Establishment (PQ-X3DH)
The session is established using a hybrid adaptation of the Extended Triple Diffie-Hellman (X3DH) protocol.

**Initiator (Alice) to Responder (Bob)**:
1. Alice retrieves Bob's PreKey Bundle (Identity Key, Signed PreKey, One-Time PreKey).
2. Alice verifies the signature on the Signed PreKey using Bob's ML-DSA-87 Identity public key.
3. Alice generates an ephemeral X25519 keypair and performs ML-KEM-768 encapsulations against Bob's Signed PreKey and One-Time PreKey.
4. The root key is derived using HKDF-SHA256 from the concatenation of:
   - `DH1 = X25519(Alice_IK, Bob_SPK)`
   - `DH2 = X25519(Alice_EK, Bob_IK)`
   - `DH3 = X25519(Alice_EK, Bob_SPK)`
   - `DH4 = X25519(Alice_EK, Bob_OPK)` (if present)
   - `PQ_SS1 = ML_KEM_Encaps(Bob_SPK_PQC)`
   - `PQ_SS2 = ML_KEM_Encaps(Bob_OPK_PQC)` (if present)

### Hybrid Double Ratchet
The Double Ratchet is adapted to include an ML-KEM ratchet alongside the classical X25519 DH ratchet.

**Mechanics**:
- When Alice sends a message, she includes her current X25519 and ML-KEM public keys.
- When Bob replies, he generates *new* X25519 and ML-KEM public keys.
- Bob performs a standard X25519 DH step with Alice's public key.
- Bob performs an ML-KEM encapsulation to Alice's ML-KEM public key, generating a KEM ciphertext.
- Both the DH shared secret and the KEM shared secret are fed into the Root Chain HKDF.
- Bob includes his new public keys and the KEM ciphertext in his reply.

This ensures **Post-Compromise Security (PCS)** against both classical and quantum adversaries.

## Threat Model

### Security Guarantees
- **Confidentiality & Integrity**: AES-256-GCM ensures that messages cannot be read or modified in transit.
- **Forward Secrecy (FS)**: Achieved via the Double Ratchet (symmetric chain ratcheting and periodic DH/KEM asymmetric ratcheting). If long-term keys are compromised, past messages remain secure.
- **Post-Compromise Security (PCS)**: If session state is compromised, subsequent asymmetric ratchet steps (using fresh X25519 and ML-KEM keys) will heal the session.
- **Post-Quantum Security**: All asymmetric operations incorporate NIST-standardized PQC algorithms (ML-KEM-768, ML-DSA-87).

### Mitigations
- **Unknown Key Share (UKS)**: Mitigated by cryptographically binding the public keys into the HKDF context (part of X3DH design).
- **Key Compromise Impersonation (KCI)**: Prevented by the `DH2 = X25519(Alice_EK, Bob_IK)` exchange in the X3DH phase.
- **Replay Attacks**: Prevented by message numbering within the symmetric ratchet. Out-of-order messages are handled strictly.
- **Metadata Leakage**: While the protocol encrypts the message content, metadata (who is talking to whom, and when) is not protected by the E2EE layer itself and must be handled by the transport layer.

## Interoperability & Serialization
The protocol uses a deterministic binary encoding designed for zero-dependency environments (e.g., `no_std` embedded systems, WASM).

- Fixed-size fields are encoded directly (e.g., 32 bytes for X25519).
- Variable-sized fields are length-prefixed with 32-bit little-endian integers.
- A `ProtocolVersion` integer allows future algorithm agility.

### Future Cryptographic Migrations
The protocol structure allows swapping primitives (e.g., to ML-KEM-1024 or future NIST signatures) by bumping the protocol version and adjusting the struct sizes.

## Constraints & Limitations
- **Message Sizing**: ML-KEM keys and ciphertexts are relatively large (1184 bytes public key, 1088 bytes ciphertext). Every ratchet step incurs an overhead of ~2.2 KB per message.
- **Asymmetric Ratchet Turn-around**: Because ML-KEM is non-interactive, a full ratchet step requires the responder to send back an encapsulation ciphertext. The initiator cannot unilaterally establish a new shared secret without sending a new public key and waiting for a ciphertext.

---
*Generated as part of the Hybrid Post-Quantum Cryptography Project.*
