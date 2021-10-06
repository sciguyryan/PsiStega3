use core::fmt::Write;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use std::{fs::File, path::Path};

use crate::error::{Error, Result};

/// Check if the current platform is little Endian.
#[allow(dead_code)]
pub fn is_little_endian() -> bool {
    let val: u32 = 0x1234;
    let val2 = val.to_le();

    val == val2
}

/// A list of the bitmasks that can check if a given but is set in a u8 value.
pub const U8_BIT_MASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// A list of the bitmasks that can be used to set the state of a bit in a u8 value.
pub const U8_UNSET_BIT_MASK: [u8; 8] = [
    255 - 1,
    255 - 2,
    255 - 4,
    255 - 8,
    255 - 16,
    255 - 32,
    255 - 64,
    255 - 128,
];

/// Check if a bitmask is set for a given u8 value.
///
/// # Arguments
///
/// * `value` - The value against which the bitmask should be checked.
/// * `index` - The bit index to be modified.
///
#[inline]
pub fn is_bit_set(value: &u8, index: usize) -> bool {
    (value & U8_BIT_MASKS[index]) != 0
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
pub fn set_bit_state(value: &mut u8, index: usize, state: bool) {
    if state {
        *value |= U8_BIT_MASKS[index];
    } else {
        *value &= U8_UNSET_BIT_MASK[index];
    }
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

/// Convert a u8 value into its binary representation.
///
/// # Arguments
///
/// * `byte` - The byte to be converted.
///
/// Note: we ignore the error condition from write! as this is
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

/// Reverse the characters in a string.
///
/// # Arguments
///
/// * `str` - The string to be reversed.
///
/// Note: this is a very basic implementation that is intended for debugging with a
/// limited character set. Do not use for an untested string.
///
#[allow(dead_code)]
pub(crate) fn reverse_string(str: &str) -> String {
    str.chars().rev().collect::<String>()
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
pub(crate) fn fill_vector_sequential(vec: &mut Vec<usize>) {
    for i in 0..vec.capacity() {
        vec.insert(i, i);
    }
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
    let total_needed = in_vec.capacity() - in_vec.len();
    let iterations = total_needed / ARRAY_SIZE;
    let remainder = total_needed - (iterations * ARRAY_SIZE);

    let mut vec1: Vec<u8> = Vec::with_capacity(total_needed);
    (0..iterations).for_each(|_| {
        let mut rand_bytes: [u8; ARRAY_SIZE] = [0; ARRAY_SIZE];
        rng.fill(&mut rand_bytes);
        vec1.extend_from_slice(&rand_bytes);
    });

    let mut vec2: Vec<u8> = (0..remainder).map(|_| rng.gen()).collect();

    in_vec.append(&mut vec1);
    in_vec.append(&mut vec2);
}

/// Read the contents of a file into a base64 string.
///
/// * `in_path` - The input file path.
///
/// `Returns:` a [`Result`] containing a base64-encoded [`String`] if the operation was successful, otherwise an [`Error`] will be returned.
///
pub fn file_to_base64_string(in_path: &str) -> Result<String> {
    use std::io::Read;

    if !Path::new(in_path).exists() {
        return Err(Error::PathInvalid);
    }

    let mut file = match File::open(&in_path) {
        Ok(f) => f,
        Err(_) => return Err(Error::File),
    };

    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_) => {}
        Err(_) => return Err(Error::FileRead),
    }

    let mut buf = String::new();
    base64::encode_config_buf(buffer, base64::STANDARD, &mut buf);

    Ok(buf)
}

/// Reads a base64 string and writes the decoded contents to a specified path.
///
/// * `b64_str` - The base64 encoded string.
/// * `out_file` - The path to which the decoded data should be written.
///
/// `Returns:` a [`Result`] indicating whether the operation was successful or not.
///
pub fn base64_string_to_file(b64_str: &str, out_file: &str) -> Result<()> {
    use std::io::Write;

    if !Path::new(out_file).exists() {
        return Err(Error::PathInvalid);
    }

    let mut buf = Vec::<u8>::new();
    match base64::decode_config_buf(b64_str, base64::STANDARD, &mut buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::Base64Decoding),
    };

    // We have decoded a valid base64 string.
    // Next we need to write the data to the file.
    let mut file = match File::create(out_file) {
        Ok(f) => f,
        Err(_) => return Err(Error::FileCreate),
    };

    // Write the resulting bytes directly into the output file.
    match file.write_all(&buf) {
        Ok(_) => {}
        Err(_) => return Err(Error::FileWrite),
    }

    Ok(())
}
