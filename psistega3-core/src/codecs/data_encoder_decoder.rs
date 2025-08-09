use rand::prelude::*;
use rand_xoshiro::Xoshiro512PlusPlus;
use std::collections::VecDeque;

/// This structure will hold the decoded data.
///
/// `Note:` this structure handles little Endian conversions internally.
///
pub struct DataDecoder {
    xor_bytes: VecDeque<u8>,
    bytes: VecDeque<u8>,
}

impl DataDecoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            xor_bytes: VecDeque::with_capacity(capacity),
            bytes: VecDeque::with_capacity(capacity / 2),
        }
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.xor_bytes.clear();
        self.bytes.clear();
    }

    /// Iterates through each XOR'ed byte and XOR pair, adds the value produced by applying the XOR operation on them to the internal list.
    ///
    pub fn decode(&mut self) {
        let len = self.xor_bytes.len() / 2;
        for _ in 0..len {
            let mut xor_value = self.xor_bytes.pop_front().unwrap();

            /*
              If the number of cells is not divisible by 2 then
                the final cell will not have a corresponding XOR cell.
              In that case the final cell value will be the XOR value.
            */
            if let Some(x) = self.xor_bytes.pop_front() {
                xor_value ^= x;
            }

            self.bytes.push_back(xor_value);
        }

        self.xor_bytes.shrink_to_fit();
    }

    /// Pop a XOR-decoded byte from the front of the byte list.
    ///
    pub fn pop_u8(&mut self) -> u8 {
        debug_assert!(!self.bytes.is_empty(), "insufficient values available");

        // We do not need to worry about decoding these values from little
        // Endian because that will have been done when loading the values.
        self.bytes.pop_front().unwrap()
    }

    /// Pop a XOR-decoded u32 from the front of the byte list.
    ///
    /// `Note:` This method will pop `4` bytes from the internal vector.
    ///
    /// `Note:` this method will automatically convert the returned value from little Endian to the correct bit-format.
    ///
    pub fn pop_u32(&mut self) -> u32 {
        debug_assert!(self.bytes.len() >= 4, "insufficient values available");

        let mut bytes = [0u8; 4];
        bytes.iter_mut().for_each(|i| {
            *i = self.pop_u8();
        });

        u32::from_le_bytes(bytes)
    }

    /// Pop a XOR-decoded vector of bytes front of the byte list.
    ///
    /// `Note:` This method will pop `2` bytes from the internal vector for each byte returned.
    ///
    pub fn pop_vec(&mut self, count: usize) -> Vec<u8> {
        debug_assert!(self.bytes.len() >= count, "insufficient values available");

        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            bytes.push(self.pop_u8());
        }

        bytes
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored in the internal vector.
    ///
    /// `Note:` this method will automatically convert the returned value from little Endian to the appropriate bit-format.
    ///
    pub fn push_u8(&mut self, value: u8) {
        self.xor_bytes.push_back(u8::from_le(value));
    }

    /// Add each byte from a slice of bytes into the XOR byte list.
    ///
    /// # Arguments
    ///
    /// * `values` - The bytes to be stored in the internal vector.
    ///
    /// `Note:` this method will automatically convert the returned value from little Endian to the appropriate bit-format.
    ///
    #[allow(dead_code)]
    pub fn push_u8_slice(&mut self, values: &[u8]) {
        for v in values {
            self.push_u8(*v);
        }
    }
}

/// This structure will hold data to be encoded into an image.
///
/// Note: this structure handles little Endian conversions internally.
///
pub struct DataEncoder {
    pub bytes: Vec<u8>,
    rng: Xoshiro512PlusPlus,
}

impl DataEncoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            rng: Xoshiro512PlusPlus::from_os_rng(),
        }
    }

    /// Fill any unused slots in the byte list with random byte data.
    ///
    #[inline]
    pub fn fill_empty_bytes(&mut self) {
        const ARRAY_SIZE: usize = 128;
        let needed = self.bytes.capacity() - self.bytes.len();
        let iterations = needed / ARRAY_SIZE;
        let remainder = needed - (iterations * ARRAY_SIZE);

        for _ in 0..iterations {
            let mut bytes: [u8; ARRAY_SIZE] = [0; ARRAY_SIZE];
            self.rng.fill(&mut bytes);
            self.bytes.extend_from_slice(&bytes);
        }

        let vec: Vec<u8> = (0..remainder).map(|_| self.rng.random()).collect();
        self.bytes.extend_from_slice(&vec);
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` This method cannot be called outside of the [`DataEncoder`] class to avoid confusion as it does not XOR encode the byte.
    ///
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
    ///
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
    ///
    #[inline]
    pub fn push_u8(&mut self, value: u8) {
        let xor = self.rng.random::<u8>().to_le();
        self.push_u8_direct(value.to_le() ^ xor);
        self.push_u8_direct(xor);
    }

    /// Add a u32 value of data into the byte list (4 bytes). Each byte will be XOR-encoded.
    ///
    /// # Arguments
    ///
    /// * `value` - The u32 to be stored.
    ///
    #[inline]
    pub fn push_u32(&mut self, value: u32) {
        self.push_u8_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests_encoder_decoder {
    use super::{DataDecoder, DataEncoder};

    #[test]
    fn encoder_fill_random() {
        let capacity = 8;
        let mut encoder = DataEncoder::new(capacity);
        encoder.fill_empty_bytes();
        assert!(encoder.bytes.len() == capacity);
    }

    #[test]
    #[should_panic(expected = "insufficient values available")]
    fn roundtrip_insufficient_values() {
        let mut encoder = DataEncoder::new(8);
        let mut decoder = DataDecoder::new(8);

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
        let mut encoder = DataEncoder::new(2);
        let mut decoder = DataDecoder::new(2);

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
        let mut encoder = DataEncoder::new(2);
        let mut decoder = DataDecoder::new(2);

        let in_val: u8 = 0xAB;
        encoder.push_u8(in_val);
        assert!(encoder.bytes.len() == 2);

        decoder.push_u8_slice(&encoder.bytes);
        // Note: decode function has not been executed here.

        let _ = decoder.pop_u8();
    }

    #[test]
    fn u8_roundtrip() {
        let mut encoder = DataEncoder::new(2);
        let mut decoder = DataDecoder::new(2);

        let in_val: u8 = 0xab;
        encoder.push_u8(in_val);
        assert!(encoder.bytes.len() == 2);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        assert!(in_val == decoder.pop_u8());
    }

    #[test]
    fn u8_slice_roundtrip() {
        let mut encoder = DataEncoder::new(8);
        let mut decoder = DataDecoder::new(8);

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
        let mut encoder = DataEncoder::new(8);
        let mut decoder = DataDecoder::new(8);

        let in_val: u32 = 0xdeadbeef;
        encoder.push_u32(in_val);
        assert!(encoder.bytes.len() == 8);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        assert!(in_val == decoder.pop_u32());
    }
}
