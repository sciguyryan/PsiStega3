use crate::error::{Error, Result};

use base64::Engine;
use core::fmt::Write;
use rand_core::{OsRng, RngCore};

/// Precomputed u8 bit masks.
pub const BIT_MASKS: [u8; 8] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80];

/// Decode a base64 string and convert it to raw vector of bytes.
///
/// * `string` - The base64 string to be decoded.
///
#[inline]
pub(crate) fn decode_base64_str_to_vec(b64_str: &str) -> Result<Vec<u8>> {
    // A base64 string is roughly 1.37 times large than the original string.
    // Since the capacity must be a usize, allocating the size
    //   of the encoded string will provide more than enough room within the
    //   vector for the output, thereby avoiding reallocation.
    base64::engine::general_purpose::STANDARD
        .decode(b64_str)
        .map_or_else(|_| Err(Error::Base64Decoding), Ok)
}

/// Encode a u8 slice as a base64 string.
///
/// * `bytes` - The slice of u8 values to be encoded.
///
#[inline]
pub(crate) fn encode_u8_slice_to_base64_str(bytes: &[u8]) -> String {
    // A base64 string is roughly 1.37 times large than the original string.
    // Since the capacity must be a usize, allocate double the capacity of the
    //   slice will avoid reallocation.
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Calculate the Shannon entropy of a byte vector.
///
/// # Arguments
///
/// * `bytes` - The slice of u8 values.
///
#[inline]
pub fn entropy(bytes: &[u8]) -> f32 {
    let mut histogram = [0u64; 256];

    for &b in bytes {
        histogram[b as usize] += 1;
    }

    // The total entropy is the sum of the probabilities
    //   of each byte occurring within a sequence.
    // The maximum total entropy is equal to the
    //   total number of microstates in each term.
    // As a byte typically consists of 8-bits in most
    //   modern systems, the maximum entropy will be 8.
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
pub fn is_bit_set(value: &u8, index: usize) -> bool {
    unsafe { (value & BIT_MASKS.get_unchecked(index)) != 0 }
}

/// Check if the current platform is little Endian.
#[allow(dead_code)]
#[inline]
pub(crate) fn is_little_endian() -> bool {
    0x1234u32 == 0x1234u32.to_le()
}

/// Attempt to find a u8 slice within a u8 slice.
///
/// # Arguments
///
/// * `haystack` - The u8 slice within which the search should be performed.
/// * `needle` - The u8 slice to search for.
///
#[inline]
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
    unsafe {
        let mask = BIT_MASKS.get_unchecked(index);
        *value = (*value & !mask) | (((state as u8) << index) & mask)
    }
}

/// Convert a u8 slice into its hexadecimal representation.
///
/// # Arguments
///
/// * `slice` - The u8 slice to be converted.
/// * `uppercase` - A boolean indicating whether the case of the hexadecimal characters.
///
/// `Note:` we ignore the error condition from write! as this is
///  completely internal and is designed for use with debug code.
///
#[allow(unused_must_use)]
#[allow(dead_code)]
#[inline]
pub(crate) fn u8_slice_to_hex(slice: &[u8], uppercase: bool) -> String {
    let mut str = String::with_capacity(2 * slice.len());
    for b in slice {
        if uppercase {
            write!(str, "{b:02X}");
        } else {
            write!(str, "{b:02x}");
        }
    }
    str
}

/// Convert a u8 slice to an 64-bit unsigned integer.
///
/// # Arguments
///
/// * `bytes` - The slice of u8 values to be converted.
///
#[inline]
pub(crate) fn u8_slice_to_u64(bytes: &[u8]) -> u64 {
    assert!(
        bytes.len() == 64,
        "Byte vector is not 64 bytes (512-bits) in length."
    );

    let arr = <[u8; 8]>::try_from(&bytes[0..8]).expect("slice with incorrect length");
    u64::from_le_bytes(arr)
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
#[inline]
pub(crate) fn u8_to_binary(byte: &u8) -> String {
    let mut str = String::with_capacity(8);
    write!(str, "{byte:08b}");
    str
}

/// Fill an array of a given length with securely generated random bytes.
#[inline]
pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    OsRng.fill_bytes(&mut arr);
    arr
}
