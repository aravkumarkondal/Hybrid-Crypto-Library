use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum E2EError {
    InvalidSignature,
    InvalidPreKeyBundle,
    SessionNotFound,
    SessionAlreadyExists,
    MessageDecryptionFailed,
    MessageOutOfOrder,
    InvalidKeyLength,
    InvalidMessageFormat,
    DoubleRatchetError,
    RatchetRollback,
    UnsupportedVersion,
    MissingOneTimePreKey,
    EncryptionError,
    DecryptionError,
    SigningError,
}

impl fmt::Display for E2EError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            E2EError::InvalidSignature => write!(f, "E2EE Error: Invalid signature"),
            E2EError::InvalidPreKeyBundle => write!(f, "E2EE Error: Invalid PreKey bundle"),
            E2EError::SessionNotFound => write!(f, "E2EE Error: Session not found"),
            E2EError::SessionAlreadyExists => write!(f, "E2EE Error: Session already exists"),
            E2EError::MessageDecryptionFailed => write!(f, "E2EE Error: Message decryption failed"),
            E2EError::MessageOutOfOrder => write!(f, "E2EE Error: Message out of order"),
            E2EError::InvalidKeyLength => write!(f, "E2EE Error: Invalid key length"),
            E2EError::InvalidMessageFormat => write!(f, "E2EE Error: Invalid message format"),
            E2EError::DoubleRatchetError => write!(f, "E2EE Error: Double Ratchet error"),
            E2EError::RatchetRollback => write!(f, "E2EE Error: Ratchet rollback detected"),
            E2EError::UnsupportedVersion => write!(f, "E2EE Error: Unsupported protocol version"),
            E2EError::MissingOneTimePreKey => write!(f, "E2EE Error: Missing One-Time PreKey"),
            E2EError::EncryptionError => write!(f, "E2EE Error: Encryption error"),
            E2EError::DecryptionError => write!(f, "E2EE Error: Decryption error"),
            E2EError::SigningError => write!(f, "E2EE Error: Signing error"),
        }
    }
}
