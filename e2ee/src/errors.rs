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
    MessageExpired,
    BackupFailed,
}

impl fmt::Display for E2EError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "E2EE Error: Invalid signature"),
            Self::InvalidPreKeyBundle => write!(f, "E2EE Error: Invalid PreKey bundle"),
            Self::SessionNotFound => write!(f, "E2EE Error: Session not found"),
            Self::SessionAlreadyExists => write!(f, "E2EE Error: Session already exists"),
            Self::MessageDecryptionFailed => write!(f, "E2EE Error: Message decryption failed"),
            Self::MessageOutOfOrder => write!(f, "E2EE Error: Message out of order"),
            Self::InvalidKeyLength => write!(f, "E2EE Error: Invalid key length"),
            Self::InvalidMessageFormat => write!(f, "E2EE Error: Invalid message format"),
            Self::DoubleRatchetError => write!(f, "E2EE Error: Double Ratchet error"),
            Self::RatchetRollback => write!(f, "E2EE Error: Ratchet rollback detected"),
            Self::UnsupportedVersion => write!(f, "E2EE Error: Unsupported protocol version"),
            Self::MissingOneTimePreKey => write!(f, "E2EE Error: Missing One-Time PreKey"),
            Self::EncryptionError => write!(f, "E2EE Error: Encryption error"),
            Self::DecryptionError => write!(f, "E2EE Error: Decryption error"),
            Self::SigningError => write!(f, "E2EE Error: Signing error"),
            Self::MessageExpired => write!(f, "E2EE Error: Message expired"),
            Self::BackupFailed => write!(f, "E2EE Error: Backup failed"),
        }
    }
}
