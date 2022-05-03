use crate::error::{Error, Result};

use core::fmt::Write;
use rand::Rng;
use rand_core::{OsRng, RngCore};

/// Decode a base64 string and convert it to raw vector of bytes.
///
/// * `string` - The base64 string to be decoded.
///
pub(crate) fn base64_string_to_vec(b64_str: &str) -> Result<Vec<u8>> {
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

/// Attempt to find a u8 slice within a u8 slice.
///
/// # Arguments
///
/// * `haystack` - The u8 slice within which the search should be performed.
/// * `needle` - The u8 slice to search for.
///
pub(crate) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

/// Convert a u8 slice to a base64 string.
///
/// * `bytes` - The slice of u8 values to be encoded.
///
pub(crate) fn u8_slice_to_base64_string(bytes: &[u8]) -> String {
    let mut buf = String::new();
    base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
    buf
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
/// `Note:` this function should `never` be changed to use the
/// lower case hexadecimal notation or it will break every file
/// encoded with an older version!
///
#[allow(unused_must_use)]
pub(crate) fn u8_slice_to_hex(arr: &[u8]) -> String {
    let mut str = String::with_capacity(2 * arr.len());
    arr.iter().for_each(|byte| {
        write!(str, "{:02X}", byte);
    });
    str
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