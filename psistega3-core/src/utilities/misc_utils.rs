use rand::SeedableRng;
use rand_xoshiro::Xoshiro512PlusPlus;

/// Precomputed u8 bit masks.
pub const BIT_MASKS: [u8; 8] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80];

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

/// Attempt to find a u8 slice within a u8 slice.
///
/// # Arguments
///
/// * `haystack` - The u8 slice within which the search should be performed.
/// * `needle` - The u8 slice to search for.
///
#[inline]
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
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
///
#[inline]
pub fn u8_slice_to_u64(bytes: &[u8]) -> u64 {
    assert!(
        bytes.len() == 64,
        "Byte vector is not 64 bytes (512-bits) in length."
    );

    let arr = <[u8; 8]>::try_from(&bytes[0..8]).expect("slice with incorrect length");
    u64::from_le_bytes(arr)
}

/// Fill an array of a given length with securely generated random bytes.
#[inline]
pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    getrandom::fill(&mut arr).expect("failed to generate random bytes");
    arr
}

#[inline]
pub fn secure_random_seed() -> u64 {
    let buff: [u8; 8] = secure_random_bytes();
    return u64::from_le_bytes(buff);
}

/// Create a securely seeded Xoshiro512PlusPlus PRNG.
#[inline]
pub fn secure_seeded_xoroshiro512() -> Xoshiro512PlusPlus {
    Xoshiro512PlusPlus::seed_from_u64(secure_random_seed())
}
