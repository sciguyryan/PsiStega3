use crate::error::{Error, Result};

use core::convert::TryFrom;

/// Version of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Version {
    /// Version 1 (0x01)
    V0x01,
    /// Version 2 (0x02)
    V0x02,
}

impl Default for Version {
    fn default() -> Self {
        Self::V0x02
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(version: u8) -> Result<Version> {
        match version {
            0x01 => Ok(Version::V0x01),
            0x02 => Ok(Version::V0x02),
            _ => Err(Error::VersionInvalid),
        }
    }
}
