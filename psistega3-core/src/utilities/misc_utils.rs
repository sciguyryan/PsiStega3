use rand::SeedableRng;
use rand_xoshiro::{Seed512, Xoshiro512PlusPlus};
use std::io::{self, Read, Write};
use zstd::{
    stream::{Decoder, Encoder},
    zstd_safe,
};

/// Precomputed u8 bit masks.
pub const BIT_MASKS: [u8; 8] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80];

const ZSTD_MAGIC: u32 = 0xFD2FB528;
const ZSTD_SKIPPABLE_START: u32 = 0x184D2A50;
const ZSTD_SKIPPABLE_END: u32 = 0x184D2A5F;

/// Validate a zstd compression level and panic if the level is invalid.
#[inline]
fn assert_valid_zstd_level(level: i32) {
    let min_level = zstd_safe::min_c_level();
    let max_level = zstd_safe::max_c_level();
    assert!(
        (min_level..=max_level).contains(&level),
        "Invalid zstd compression level: {level}. Level which must be => {min_level} and <= {max_level})",
    );
}

/// Compress a byte slice and return the compressed data as a Vec<u8>.
///
/// # Arguments
/// * `data` - The byte slice to be compressed.
/// * `level` - The compression level to be used, which can be an integer from 1 to 22, where higher levels indicate better compression at the cost of increased time and memory usage.
#[inline]
pub fn compress(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    assert_valid_zstd_level(level);

    let mut compressed = Vec::new();
    let mut encoder = Encoder::new(&mut compressed, level)?;
    encoder.write_all(data)?;
    encoder.finish()?;

    Ok(compressed)
}

/// Compress a byte slice and return the compressed data as a Vec<u8>.
#[inline]
pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut decoder = Decoder::new(data)?;
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Check if a bit is set for a given u8 value.
///
/// # Arguments
///
/// * `value` - The value against which the bit should be checked.
/// * `index` - The bit index to be modified.
#[inline]
pub fn is_bit_set(value: &u8, index: usize) -> bool {
    unsafe { (value & BIT_MASKS.get_unchecked(index)) != 0 }
}

/// Returns true if the buffer begins with a valid zstd frame magic value.
#[inline]
pub fn is_zstd_frame(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    magic == ZSTD_MAGIC || (ZSTD_SKIPPABLE_START..=ZSTD_SKIPPABLE_END).contains(&magic)
}

/// Attempt to find a u8 slice within a u8 slice.
///
/// # Arguments
///
/// * `haystack` - The u8 slice within which the search should be performed.
/// * `needle` - The u8 slice to search for.
#[inline]
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Fill an array of a given length with securely generated random bytes.
#[inline]
pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    getrandom::fill(&mut arr).expect("failed to generate random bytes");
    arr
}

/// Create a securely seeded Xoshiro512PlusPlus PRNG.
#[inline]
pub fn secure_seeded_xoroshiro512() -> Xoshiro512PlusPlus {
    Xoshiro512PlusPlus::from_seed(Seed512(secure_random_bytes()))
}

/// Set the state of a bit in a u8 value.
///
/// # Arguments
///
/// * `value` - The u8 value to be modified.
/// * `index` - The bit index to be modified.
/// * `state` - The final state of the bit.
#[inline]
pub fn set_bit_state(value: &mut u8, index: usize, state: bool) {
    unsafe {
        let mask = BIT_MASKS.get_unchecked(index);
        *value = (*value & !mask) | (((state as u8) << index) & mask)
    }
}

/// Convert a u8 slice to an 64-bit unsigned integer.
///
/// # Arguments
///
/// * `bytes` - The slice of u8 values to be converted.
#[inline]
pub fn u8_slice_to_u64(bytes: &[u8]) -> u64 {
    assert!(
        bytes.len() >= 8,
        "Byte vector is not at least 8 bytes (64-bits) in length."
    );

    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}
