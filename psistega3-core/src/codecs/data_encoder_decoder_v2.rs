use std::collections::VecDeque;

use rand::RngExt;
use rand_xoshiro::Xoshiro512PlusPlus;

use crate::utilities::misc_utils;

/// This structure will hold the decoded data.
///
/// `Note:` this structure handles little Endian conversions internally.
pub struct DataDecoderV2 {
    xor_bytes: VecDeque<u8>,
    bytes: Vec<u8>,
    read_idx: usize,
}

impl DataDecoderV2 {
    pub fn new(capacity: usize) -> Self {
        Self {
            xor_bytes: VecDeque::with_capacity(capacity),
            bytes: Vec::with_capacity(capacity / 2 + 1),
            read_idx: 0,
        }
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.xor_bytes.clear();
        self.bytes.clear();
        self.read_idx = 0;
    }

    /// Iterates through each XOR'ed byte and XOR pair, adds the value produced
    /// by applying the XOR operation on them to the internal list.
    pub fn decode(&mut self) {
        // Reserve capacity to avoid reallocations.
        self.bytes.clear();

        let mut i = 0;
        let len = self.xor_bytes.len();

        // Process all full (normal) pairs.
        while i + 1 < len {
            // Safe indexing; no bounds checks in debug due to while condition.
            self.bytes.push(self.xor_bytes[i] ^ self.xor_bytes[i + 1]);
            i += 2;
        }

        // Handle the final byte if the length is odd.
        if i < len {
            self.bytes.push(self.xor_bytes[i]);
        }

        // Clear input buffer and reset read index.
        self.xor_bytes.clear();
        self.read_idx = 0;
    }

    /// Pop a XOR-decoded byte from the front of the byte list.
    pub fn pop_u8(&mut self) -> u8 {
        assert!(
            self.read_idx < self.bytes.len(),
            "insufficient values available"
        );

        let v = unsafe { *self.bytes.get_unchecked(self.read_idx) };
        self.read_idx += 1;
        v
    }

    /// Pop a XOR-decoded u32 from the front of the byte list.
    ///
    /// `Note:` This method will pop `4` bytes from the internal vector.
    ///
    /// `Note:` this method will automatically convert the returned value
    /// from little Endian to the correct bit-format.
    pub fn pop_u32(&mut self) -> u32 {
        assert!(
            self.bytes.len() - self.read_idx >= 4,
            "insufficient values available"
        );

        let b0 = self.pop_u8();
        let b1 = self.pop_u8();
        let b2 = self.pop_u8();
        let b3 = self.pop_u8();

        u32::from_le_bytes([b0, b1, b2, b3])
    }

    /// Pop a XOR-decoded vector of bytes from the front of the byte list.
    pub fn pop_vec(&mut self, count: usize) -> Vec<u8> {
        assert!(
            self.bytes.len() - self.read_idx >= count,
            "insufficient values available"
        );

        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.pop_u8());
        }
        out
    }

    /// Add a byte of data into the XOR byte list.
    pub fn push_u8(&mut self, value: u8) {
        self.xor_bytes.push_back(value);
    }

    /// Add each byte from a slice of bytes into the XOR byte list.
    #[allow(dead_code)]
    pub fn push_u8_slice(&mut self, values: &[u8]) {
        for &v in values {
            self.push_u8(v);
        }
    }
}

/// This structure will hold data to be encoded into an image.
///
/// Note: this structure handles little Endian conversions internally.
///
pub struct DataEncoderV2 {
    pub bytes: Vec<u8>,
    rng: Xoshiro512PlusPlus,
}

impl DataEncoderV2 {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            rng: misc_utils::secure_seeded_xoroshiro512(),
        }
    }

    /// Fill any unused slots in the byte list with random byte data.
    #[inline]
    pub fn fill_empty_bytes(&mut self) {
        debug_assert!(self.bytes.len() <= self.bytes.capacity());

        const ARRAY_SIZE: usize = 128;
        let needed = self.bytes.capacity() - self.bytes.len();
        let iterations = needed / ARRAY_SIZE;
        let remainder = needed - (iterations * ARRAY_SIZE);

        for _ in 0..iterations {
            let mut bytes: [u8; ARRAY_SIZE] = [0; ARRAY_SIZE];
            self.rng.fill(&mut bytes);
            self.bytes.extend_from_slice(&bytes);
        }

        let mut tail = [0u8; ARRAY_SIZE];
        self.rng.fill(&mut tail[..remainder]);
        self.bytes.extend_from_slice(&tail[..remainder]);
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` This method cannot be called outside of the [`DataEncoder`] class to avoid confusion as it does not XOR encode the byte.
    #[inline]
    fn push_u8_direct(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Push a sequence of bytes from a slice into the byte list. Each byte will be XOR-encoded.
    ///
    /// # Arguments
    ///
    /// * `slice` - The slice of bytes to be stored.
    ///
    /// `Note:` byte yielded by the slice will be added `2` bytes to the internal byte list.
    ///
    /// `Note:` the 1st byte will be the XOR-encoded data and the second will be the XOR value byte.
    #[inline]
    pub fn push_u8_slice(&mut self, slice: &[u8]) {
        for b in slice {
            self.push_u8(*b);
        }
    }

    /// Push a byte into the byte list. The byte will be XOR-encoded.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` every byte added will add `2` bytes to the internal byte list.
    ///
    /// `Note:` the 1st byte will be the XOR-encoded data and the second will be the XOR value byte.
    #[inline]
    pub fn push_u8(&mut self, value: u8) {
        let xor = self.rng.random::<u8>();
        self.push_u8_direct(value.to_le() ^ xor);
        self.push_u8_direct(xor);
    }

    /// Add a u32 value of data into the byte list (4 bytes). Each byte will be XOR-encoded.
    ///
    /// # Arguments
    ///
    /// * `value` - The u32 to be stored.
    #[inline]
    pub fn push_u32(&mut self, value: u32) {
        self.push_u8_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests_encoder_decoder {
    use super::{DataDecoderV2, DataEncoderV2};

    #[test]
    fn encoder_fill_random() {
        let capacity = 8;
        let mut encoder = DataEncoderV2::new(capacity);
        encoder.fill_empty_bytes();
        assert!(encoder.bytes.len() == capacity);
    }

    #[test]
    #[should_panic(expected = "insufficient values available")]
    fn roundtrip_insufficient_values() {
        let mut encoder = DataEncoderV2::new(8);
        let mut decoder = DataDecoderV2::new(8);

        let in_val: u8 = 0xab;
        encoder.push_u8(in_val);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        // This should fail as there will not be enough bytes to pop from the vector.
        let _ = decoder.pop_u32();
    }

    #[test]
    #[should_panic(expected = "insufficient values available")]
    fn roundtrip_no_values() {
        let mut encoder = DataEncoderV2::new(2);
        let mut decoder = DataDecoderV2::new(2);

        let in_val: u8 = 0xab;
        encoder.push_u8(in_val);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        // The second call should fail as there will be no bytes to pop
        // from the vector.
        let _ = decoder.pop_u8();
        let _ = decoder.pop_u8();
    }

    #[test]
    #[should_panic(expected = "insufficient values available")]
    fn roundtrip_not_decoded() {
        let mut encoder = DataEncoderV2::new(2);
        let mut decoder = DataDecoderV2::new(2);

        let in_val: u8 = 0xAB;
        encoder.push_u8(in_val);
        assert!(encoder.bytes.len() == 2);

        decoder.push_u8_slice(&encoder.bytes);
        // Note: decode function has not been executed here.

        let _ = decoder.pop_u8();
    }

    #[test]
    fn u8_roundtrip() {
        let mut encoder = DataEncoderV2::new(2);
        let mut decoder = DataDecoderV2::new(2);

        let in_val: u8 = 0xab;
        encoder.push_u8(in_val);
        assert!(encoder.bytes.len() == 2);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        assert!(in_val == decoder.pop_u8());
    }

    #[test]
    fn u8_slice_roundtrip() {
        let mut encoder = DataEncoderV2::new(8);
        let mut decoder = DataDecoderV2::new(8);

        let in_val: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
        encoder.push_u8_slice(&in_val);
        assert!(encoder.bytes.len() == 8);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        let out_val = decoder.pop_vec(4);
        assert!(in_val[..] == out_val[..]);
    }

    #[test]
    fn u32_roundtrip() {
        let mut encoder = DataEncoderV2::new(8);
        let mut decoder = DataDecoderV2::new(8);

        let in_val: u32 = 0xdeadbeef;
        encoder.push_u32(in_val);
        assert!(encoder.bytes.len() == 8);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        assert!(in_val == decoder.pop_u32());
    }
}
