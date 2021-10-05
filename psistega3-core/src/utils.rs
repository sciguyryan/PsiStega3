use core::fmt::Write;
use rand::Rng;
use rand_core::{OsRng, RngCore};

/// Check if the current platform is little Endian.
#[allow(dead_code)]
pub(crate) fn is_little_endian() -> bool {
    let val: u32 = 0x1234;
    let val2 = val.to_le();

    val == val2
}

/// A list of the bitmasks that can check if a given but is set in a u8 value.
pub(crate) const U8_BIT_MASKS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// A list of the bitmasks that can be used to set the state of a bit in a u8 value.
const U8_UNSET_BIT_MASK: [u8; 8] = [
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
pub(crate) fn is_bit_set(value: &u8, index: usize) -> bool {
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
pub(crate) fn set_bit_state(value: &mut u8, index: usize, state: bool) {
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
