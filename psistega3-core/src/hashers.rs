use crate::{
    error::{Error, Result},
    macros::*,
};

use argon2::Argon2;
use memmap2::Mmap;
use sha3::{Digest, Sha3_512};
use std::fs::File;

/// Get the Argon2 hash of a string slice.
///
/// # Arguments
///
/// * `key_bytes` - The key bytes to be hashed.
/// * `salt` - A 12-byte array of random values.
/// * `m_cost` - The memory cost (in kilobytes) to be applied to the Argon2 hashing function.
/// * `p_cost` - The parallel cost (in threads) to be applied to the Argon2 hashing function.
/// * `t_cost` - The time cost (in iterations) to be applied to the Argon2 hashing function.
/// * `version` - The version of the Argon2 hashing function to be used.
///
pub fn argon2_string(
    key_bytes: &[u8],
    salt: [u8; 12],
    m_cost: u32,
    p_cost: u32,
    t_cost: u32,
    version: argon2::Version,
) -> Result<[u8; 128]> {
    let mut builder = argon2::ParamsBuilder::new();

    if builder.m_cost(m_cost).is_err()
        || builder.p_cost(p_cost).is_err()
        || builder.t_cost(t_cost).is_err()
    {
        return Err(Error::Argon2InvalidParams);
    };

    // This method return an error condition if any of supplied parameters
    //   are incorrect prior to this statement.
    // This unwrap should be safe as a result.
    let params = builder.params().unwrap();

    // Construct the hasher.
    let hasher = Argon2::new(argon2::Algorithm::Argon2id, version, params);

    // Nom!
    let mut hashed_bytes = [0u8; 128];
    unwrap_res_or_return!(
        hasher.hash_password_into(key_bytes, &salt, &mut hashed_bytes),
        Err(Error::Argon2NoHash)
    );

    Ok(hashed_bytes)
}

/// Get the CRC32 hash of a u8 slice.
///
/// # Arguments
///
/// * `slice` - The u8 slice to be hashed.
///
pub fn crc32_slice(slice: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(slice);
    hasher.finalize()
}

/// Get the SHA3-512 hashing of a specified file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub fn sha3_512_file(path: &str) -> Result<Vec<u8>> {
    let file = unwrap_res_or_return!(File::open(path), Err(Error::FileHashingError));

    // Create a read-only memory map of the file as it should improve
    // the performance of this function.
    let mmap = unsafe { unwrap_res_or_return!(Mmap::map(&file), Err(Error::FileHashingError)) };

    let mut hasher = Sha3_512::new();
    for c in mmap.chunks(16384) {
        hasher.update(c);
    }

    Ok(hasher.finalize().to_vec())
}

/// Get the SHA3-512 hash of a string slice.
///
/// # Arguments
///
/// * `str` - The string slice to be hashed.
///
#[cfg(test)]
pub fn sha3_512_string(str: &str) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(&str);
    hasher.finalize().to_vec()
}

/// Get the SHA3-512 hash of a u8 slice.
///
/// # Arguments
///
/// * `bytes` - The byte slice to be hashed.
///
pub fn sha3_512_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}
