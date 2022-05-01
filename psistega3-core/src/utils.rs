use crate::error::{Error, Result};
use crate::macros::*;

use core::fmt::Write;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// The IEND chunk of a PNG file.
pub(crate) const IEND: [u8; 12] = [0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82];

/// The ZTXT chunk header of a PNG file.
pub(crate) const ZTXT: [u8; 4] = [0x7a, 0x54, 0x58, 0x74];

/// Decode a base64 string and convert it to raw vector of bytes.
///
/// * `string` - The base64 string to be decoded.
///
pub(crate) fn base64_string_to_vector(b64_str: &str) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
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

/// Check if a bit is set for a given u8 value.
///
/// # Arguments
///
/// * `value` - The value against which the bit should be checked.
/// * `index` - The bit index to be modified.
///
#[inline]
pub(crate) fn is_bit_set(value: &u8, index: usize) -> bool {
    ((value >> index) & 1) == 1
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
    (0..iterations).for_each(|_| {
        let mut bytes: [u8; ARRAY_SIZE] = [0; ARRAY_SIZE];
        rng.fill(&mut bytes);
        vec1.extend_from_slice(&bytes);
    });

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

pub(crate) fn find_png_ztxt_chunk_start(path: &str) -> Option<usize> {
    use memmap2::Mmap;

    let file = unwrap_or_return_val!(File::open(path), None);

    // Create a read-only memory map of the file as it should improve
    // the performance of this function.
    let mmap = unsafe { unwrap_or_return_val!(Mmap::map(&file), None) };

    let index = find_subsequence(&mmap, &ZTXT)?;

    // The start of the chunk is always four bytes behind the header.
    // The initial four bytes of the chunk indicate the length of the chunk.
    Some(index - 4)
}

pub(crate) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

    if !path_exists(path) {
        return Err(Error::PathInvalid);
    }

    let mut file = unwrap_or_return_err!(File::open(&path), Error::File);
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
    *value = (*value & !(1 << index)) | ((state as u8) << index)
}

/// Attempt to truncate a set number of bytes from the end of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `bytes_to_trim` - The number of bytes to be trimmed from the end of the file.
///
pub(crate) fn truncate_file(path: &str, bytes_to_trim: u64) -> Result<()> {
    let file = unwrap_or_return_err!(File::options().write(true).open(path), Error::File);
    let meta = unwrap_or_return_err!(file.metadata(), Error::FileMetadata);

    // Calculate the new file length.
    let new_len = meta.len() - bytes_to_trim;

    // Truncate the file.
    if file.set_len(new_len).is_err() {
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
/// `Note:` we ignore the error condition from write! as this is
///  completely internal and is designed for use with debug code.
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
///  completely internal and is designed for use with debug code.
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
    let mut file = unwrap_or_return_err!(File::create(&out_file), Error::FileCreate);

    // Write the resulting bytes directly into the output file.
    match file.write_all(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::FileWrite),
    }
}
