use core::fmt::Write;
use std::ffi::OsStr;
use std::path::Path;

pub fn is_bit_set(bit: &u8, value: &u8) -> bool {
    (value & (1 << bit)) == 1
}

// TODO: remove the error conditions, if they are slowing things down.
pub fn u8_array_to_hex(arr: &[u8]) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(2 * arr.len());
    for byte in arr {
        if let Err(e)  = write!(str, "{:02X}", byte) {
            return Err(e)
        }
    }
    Ok(str)
}

// TODO: remove the error conditions, if they are slowing things down.
pub fn u8_to_binary(byte: &u8) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(8);
    if let Err(e)  = write!(str, "{:08b}", byte) {
        return Err(e)
    }
    Ok(str)
}

pub fn path_has_extension(path: &str, extension: &str) -> bool {
    path_has_any_extension(path, vec![extension])
}

pub fn path_has_any_extension(path: &str, extensions: Vec<&str>) -> bool {
    match Path::new(path).extension().and_then(OsStr::to_str) {
        Some(e) => {
            extensions.iter().any(|&ext| ext == e)
        },
        _ => {
            false
        }
    }
}
