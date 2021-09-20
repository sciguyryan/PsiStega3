use core::fmt::Write;
use rand_core::{OsRng, RngCore};
use std::ffi::OsStr;
use std::path::Path;

/// Check if the current platform is little Endian.
pub fn is_little_endian() -> bool {
    let val: u32 = 0x1234;
    let val2 = val.to_le();

    val == val2
}

/// A list of the bitmasks that can be applied to a u8 value.
pub const U8_BIT_MASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// Check if a bitmask is set for a given u8 value.
///
/// # Arguments
///
/// * `value` - The value against which the bitmask should be checked.
/// * `mask` - The bitmask to be applied.
pub fn is_bit_set(value: &u8, mask: &u8) -> bool {
    (value & mask) != 0
}

/// Convert a u8 slice into its hexadecimal representation.
///
/// # Arguments
///
/// * `arr` - The u8 slice to be converted.
///
/// Note: we ignore the error condition from write! as this is
/// completely internal and is designed for use with debug code.
#[allow(unused_must_use)]
pub fn u8_array_to_hex(arr: &[u8]) -> String {
    let mut str = String::with_capacity(2 * arr.len());
    for byte in arr {
        write!(str, "{:02X}", byte);
    }
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
#[allow(unused_must_use)]
pub fn u8_to_binary(byte: &u8) -> String {
    let mut str = String::with_capacity(8);
    write!(str, "{:08b}", byte);
    str
}

/// Extension the extension from the specified path.
///
/// # Arguments
///
/// * `path` - The path from which the extension should be extracted.
///
/// Note: in the case where no extension is present, this function will
/// will return an empty string.
pub fn get_extension(path: &str) -> &OsStr {
    match Path::new(path).extension() {
        Some(e) => e,
        None => OsStr::new(""),
    }
}

/// Fill an array of a given length with securely generated random bytes.
pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
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
pub fn reverse_string(str: &String) -> String {
    str.chars().rev().collect::<String>()
}
