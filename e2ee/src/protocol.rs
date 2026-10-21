use crate::errors::E2EError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1 = 1,
}

impl ProtocolVersion {
    pub const fn from_u16(val: u16) -> Result<Self, E2EError> {
        match val {
            1 => Ok(Self::V1),
            _ => Err(E2EError::UnsupportedVersion),
        }
    }

    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}
