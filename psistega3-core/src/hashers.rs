use crate::error::{Error, Result};

use argon2::Argon2;
use sha3::{Digest, Sha3_512};
use std::{fs::File, io};

/// Compute the Argon2 hash of a string slice.
///
/// # Arguments
///
/// * `key_bytes` - The key bytes to be hashed.
/// * `salt` - A 12-byte array of random values.
/// * `m_cost` - The memory cost (in kilobytes) to be applied to the Argon2 hashing function.
/// * `p_cost` - The parallel cost (in threads) to be applied to the Argon2 hashing function.
/// * `t_cost` - The time cost (in iterations) to be applied to the Argon2 hashing function.
/// * `version` - The version of the Argon2 hashing function to be used.
#[inline]
pub fn argon2_string(
    key_bytes: &[u8],
    salt: &[u8],
    m_cost: u32,
    p_cost: u32,
    t_cost: u32,
    version: argon2::Version,
) -> Result<[u8; 128]> {
    // Return an error if any of supplied parameters are incorrect.
    let Ok(params) = argon2::Params::new(m_cost, t_cost, p_cost, None) else {
        return Err(Error::Argon2InvalidParams);
    };

    let hasher = Argon2::new(argon2::Algorithm::Argon2id, version, params);

    let mut hashed_bytes = [0u8; 128];
    let Ok(_) = hasher.hash_password_into(key_bytes, &salt, &mut hashed_bytes) else {
        return Err(Error::Argon2NoHash);
    };

    Ok(hashed_bytes)
}

/// Compute the CRC32 hash of a u8 slice.
///
/// # Arguments
///
/// * `slice` - The u8 slice to be hashed.
#[inline]
pub fn crc32_slice(slice: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(slice);
    hasher.finalize()
}

/// Compute the SHA3-512 hash of a u8 slice.
///
/// # Arguments
///
/// * `bytes` - The byte slice to be hashed.
#[inline]
pub fn sha3_512_bytes(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Compute the SHA3-512 hashing of a specified file.
///
/// # Arguments
///
/// * `path` - The path to the file.
#[inline]
pub fn sha3_512_file(path: &str) -> Result<[u8; 64]> {
    let mut file = File::open(path).map_err(|_| Error::FileHashingError)?;

    let mut hasher = Sha3_512::new();
    io::copy(&mut file, &mut hasher).map_err(|_| Error::FileHashingError)?;

    Ok(hasher.finalize().into())
}

/// Compute the SHA3-512 over a sequence of byte slices.
///
/// # Arguments
///
/// * `slices` - A slide of u8 slices to be hashed.
#[inline]
pub fn sha3_512_slices(slices: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();

    for slice in slices {
        hasher.update(slice);
    }

    hasher.finalize().into()
}

/// Compute the SHA3-512 hash of a string slice.
///
/// # Arguments
///
/// * `str` - The string slice to be hashed.
#[cfg(test)]
#[inline]
pub fn sha3_512_string(str: &str) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(str);
    hasher.finalize().into()
}
