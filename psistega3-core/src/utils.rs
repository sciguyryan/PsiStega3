use crate::error::{Error, Result};

use core::fmt::Write;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// A list of the bitmasks that can check if a given but is set in a u8 value.
pub(crate) const U8_BIT_MASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// A list of the bitmasks that can be used to set the state of a bit in a u8 value.
pub(crate) const U8_UNSET_BIT_MASK: [u8; 8] = [
    255 - 1,
    255 - 2,
    255 - 4,
    255 - 8,
    255 - 16,
    255 - 32,
    255 - 64,
    255 - 128,
];

/// Decode a base64 string and convert it to raw vector of bytes.
///
/// * `string` - The base64 string to be decoded.
///
pub(crate) fn base64_string_to_vector(b64_str: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::<u8>::new();
    match base64::decode_config_buf(&b64_str, base64::STANDARD, &mut buf) {
        Ok(_) => Ok(buf),
        Err(_) => Err(Error::Base64Decoding),
    }
}

/// Calculate the Shannon entropy of a byte vector.
///
/// # Arguments
///
/// * `bytes` - The slice of u8 values.
///
pub fn entropy(bytes: &[u8]) -> f32 {
    let mut histogram = [0u64; 256];

    for &b in bytes {
        histogram[b as usize] += 1;
    }

    // The total entropy is the sum of the probabilities
    // of each byte occurring within a sequence.
    // The maximum total entropy is equal to the
    // total number of microstates in each term.
    // As a byte typically consists of 8-bits in most
    // modern systems, the maximum entropy will be 8.
    // The closer to 8, the higher the total entropy is.
    let len = bytes.len();
    histogram
        .iter()
        .cloned()
        .filter(|&v| v != 0)
        .map(|v| v as f32 / len as f32)
        .map(|r| -r * r.log2())
        .sum()
}

/// Check if a bitmask is set for a given u8 value.
///
/// # Arguments
///
/// * `value` - The value against which the bitmask should be checked.
/// * `index` - The bit index to be modified.
///
#[inline]
pub(crate) fn is_bit_set(value: &u8, index: usize) -> bool {
    (value & U8_BIT_MASKS[index]) != 0
}

/// Check if the current platform is little Endian.
#[allow(dead_code)]
pub(crate) fn is_little_endian() -> bool {
    0x1234u32 == 0x1234u32.to_le()
}

/// Fill a u8 vector with randomly generated values.
///
/// * `in_vec` - The vector to be filled with u8 values.
/// * `rng` - The random number generator that will be used to generate the values.
///
/// Note: this method is intended to be called on vectors that have a predefined
/// capacity.
///
#[inline]
pub(crate) fn fast_fill_vec_random<T>(in_vec: &mut Vec<u8>, rng: &mut T)
where
    T: RngCore,
{
    const ARRAY_SIZE: usize = 64;
    let needed = in_vec.capacity() - in_vec.len();
    let iterations = needed / ARRAY_SIZE;
    let remainder = needed - (iterations * ARRAY_SIZE);

    let mut vec1: Vec<u8> = Vec::with_capacity(needed);
    for _ in 0..iterations {
        let mut bytes: [u8; ARRAY_SIZE] = [0; ARRAY_SIZE];
        rng.fill(&mut bytes);
        vec1.extend_from_slice(&bytes);
    }

    let mut vec2: Vec<u8> = (0..remainder).map(|_| rng.gen()).collect();

    in_vec.append(&mut vec1);
    in_vec.append(&mut vec2);
}

/// Fills a vector with sequential values.
///
/// # Arguments
///
/// * `vec` - The vector to be filled with values.
///
/// Note: this method will only operate as expected if an explicit
/// capacity has been specified.
///
#[inline]
pub(crate) fn fill_vector_sequential(vec: &mut Vec<usize>) {
    (0..vec.capacity()).for_each(|i| {
        vec.push(i);
    });
}

/// Get the path to the current execution directory.
#[allow(dead_code)]
pub(crate) fn get_current_dir() -> PathBuf {
    std::env::current_dir().unwrap()
}

/// Check if the specified path is valid and exists.
///
/// * `path` - The path to be checked.
///
#[inline]
pub(crate) fn path_exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Read a file into a u8 vector.
///
/// * `path` - The path to the file.
///
pub(crate) fn read_file_to_u8_vector(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    if !Path::new(path).exists() {
        return Err(Error::PathInvalid);
    }

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Err(Error::File),
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_) => Ok(buffer),
        Err(_) => Err(Error::FileRead),
    }
}

/// Set the state of a bit in a u8 value.
///
/// # Arguments
///
/// * `value` - The u8 value to be modified.
/// * `index` - The bit index to be modified.
/// * `state` - The final state of the bit.
///
#[inline]
pub(crate) fn set_bit_state(value: &mut u8, index: usize, state: bool) {
    if state {
        *value |= U8_BIT_MASKS[index];
    } else {
        *value &= U8_UNSET_BIT_MASK[index];
    }
}

/// Attempt to truncate a set number of bytes from the end of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `bytes_to_trim` - The number of bytes to be trimmed from the end of the file.
///
pub(crate) fn truncate_file(path: &str, bytes_to_trim: u64) -> Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(path);
    if f.is_err() {
        return Err(Error::File);
    }
    let f = f.unwrap();

    let meta = f.metadata();
    if meta.is_err() {
        return Err(Error::FileMetadata);
    }

    // Calculate the new file length.
    let new_len = meta.unwrap().len() - bytes_to_trim;

    // Truncate the file.
    if f.set_len(new_len).is_err() {
        return Err(Error::FileTruncate);
    }

    Ok(())
}

/// Convert a u8 slice into its hexadecimal representation.
///
/// # Arguments
///
/// * `arr` - The u8 slice to be converted.
///
/// Note: we ignore the error condition from write! as this is
/// completely internal and is designed for use with debug code.
///
#[allow(unused_must_use)]
pub(crate) fn u8_array_to_hex(arr: &[u8]) -> String {
    let mut str = String::with_capacity(2 * arr.len());
    arr.iter().for_each(|byte| {
        write!(str, "{:02X}", byte);
    });
    str
}

/// Convert a u8 slice to a base64 string.
///
/// * `bytes` - The slice of u8 values to be encoded.
///
pub(crate) fn u8_slice_to_base64_string(bytes: &[u8]) -> String {
    let mut buf = String::new();
    base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
    buf
}

/// Convert a u8 value into its binary representation.
///
/// # Arguments
///
/// * `byte` - The byte to be converted.
///
/// `Note:` we ignore the error condition from write! as this is
/// completely internal and is designed for use with debug code.
///
#[allow(unused_must_use, dead_code)]
pub(crate) fn u8_to_binary(byte: &u8) -> String {
    let mut str = String::with_capacity(8);
    write!(str, "{:08b}", byte);
    str
}

/// Fill an array of a given length with securely generated random bytes.
pub(crate) fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    OsRng.fill_bytes(&mut arr);
    arr
}

/// Write a u8 slice to an output file.
///
/// * `out_file` - The path to the file.
/// * `bytes` - The slice of u8 values to be written to the file.
///
pub(crate) fn write_u8_slice_to_file(out_file: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    // We have decoded a valid base64 string.
    // Next we need to write the data to the file.
    let mut file = match File::create(&out_file) {
        Ok(f) => f,
        Err(_) => return Err(Error::FileCreate),
    };

    // Write the resulting bytes directly into the output file.
    match file.write_all(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::FileWrite),
    }
}
