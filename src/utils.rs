use core::fmt::Write;
use std::ffi::OsStr;
use std::path::Path;

use rand_core::{OsRng, RngCore};

pub fn is_little_endian() -> bool {
    let val: u32 = 0x1234;
    let val2 = val.to_le();

    val == val2
}

pub fn is_bit_set(value: u8, bit: u8) -> bool {
    (value & (1 << bit)) != 0
}

pub const U8_BIT_MASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
pub fn is_bit_set2(value: &u8, mask: &u8) -> bool {
    (value & mask) != 0
}

pub fn u8_array_to_hex(arr: &[u8]) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(2 * arr.len());
    for byte in arr {
        write!(str, "{:02X}", byte)?;
    }
    Ok(str)
}

pub fn u8_to_binary(byte: &u8) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(8);
    write!(str, "{:08b}", byte)?;
    Ok(str)
}

pub fn path_has_extension(path: &str, extension: &str) -> bool {
    path_has_any_extension(path, vec![extension])
}

pub fn path_has_any_extension(path: &str, extensions: Vec<&str>) -> bool {
    match Path::new(path).extension().and_then(OsStr::to_str) {
        Some(e) => extensions.iter().any(|&ext| ext == e),
        _ => false,
    }
}

pub fn get_extension(path: &str) -> &OsStr {
    match Path::new(path).extension() {
        Some(e) => e,
        None => OsStr::new(""),
    }
}

pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    OsRng.fill_bytes(&mut arr);

    arr
}