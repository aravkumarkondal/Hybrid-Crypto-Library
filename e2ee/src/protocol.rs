use crate::errors::E2EError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1 = 1,
}

impl ProtocolVersion {
    pub fn from_u16(val: u16) -> Result<Self, E2EError> {
        match val {
            1 => Ok(ProtocolVersion::V1),
            _ => Err(E2EError::UnsupportedVersion),
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}
