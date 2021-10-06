use crate::error::{Error, Result};

use core::convert::TryFrom;

/// Version of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Version {
    /// Version 1 (0x01 in hex)
    V0x01,
}

impl Default for Version {
    fn default() -> Self {
        Self::V0x01
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(version: u8) -> Result<Version> {
        match version {
            0x01 => Ok(Version::V0x01),
            _ => Err(Error::VersionInvalid),
        }
    }
}
