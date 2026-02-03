use crate::{
    codecs::codec::Codec,
    error::{Error, Result},
    hashers,
    image_wrapper::ImageWrapper,
    logger::Logger,
    utilities::*,
};

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use rand::prelude::*;
use rand_xoshiro::Xoshiro512PlusPlus;
use std::convert::TryInto;
use zeroize::Zeroize;

use super::{
    codec::Config,
    data_encoder_decoder::{DataDecoder, DataEncoder},
};

/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const M_COST: u32 = 65_536;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VER: argon2::Version = argon2::Version::V0x13;
/// The version of this codec.
const CODED_VERSION: u8 = 0x3;

/// The struct that holds the v2 steganography algorithm.
pub struct StegaV3 {
    /// The data index to cell ID map.
    data_cell_vec: Vec<usize>,
    /// If the noise layer should be applied to the output image.
    noise_layer: bool,
    /// If the resulting image file should be saved when encoding.
    output_files: bool,
    /// The logger instance for this codec.
    logger: Logger,
    // The RNG for the cell value adjustments.
    position_rng: Xoshiro512PlusPlus,
    // The Argon2 time cost.
    t_cost: u32,
    // The Argon2 parallel cost.
    p_cost: u32,
    // The Argon2 memory cost.
    m_cost: u32,
}

impl StegaV3 {
    pub fn new() -> Self {
        Self {
            data_cell_vec: Vec::new(),
            noise_layer: true,
            output_files: true,
            logger: Logger::new(false),
            position_rng: Xoshiro512PlusPlus::from_os_rng(),
            t_cost: T_COST,
            p_cost: P_COST,
            m_cost: M_COST,
        }
    }

    /// Builds a map of data indices to cell indices.
    ///
    /// # Arguments
    ///
    /// * `key` - The key bytes that should be used to seed the random number generator.
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    fn build_data_to_cell_index_map(&mut self, img: &ImageWrapper, key: &[u8]) {
        /*
          When we can't use the Argon2 hash for the positional RNG
            as we will need the salt, which will not be available when
            initially reading the data from the file.
        */
        let bytes = hashers::sha3_512_bytes(key);
        let seed = misc_utils::u8_slice_to_u64(&bytes);
        let mut rng = Xoshiro512PlusPlus::seed_from_u64(seed);

        // It doesn't matter if we call this on reference or encoded
        //   as they will have the same value at this point.
        let total_cells = StegaV3::get_total_cells(img);

        // Pre-allocate vector and map for performance.
        let mut cell_list: Vec<usize> = Vec::with_capacity(total_cells);
        cell_list.extend(0..total_cells);

        // Randomize the order of the cell IDs.
        cell_list.shuffle(&mut rng);

        // Pre-allocate map for performance.
        self.data_cell_vec = cell_list.into_iter().collect();
    }

    #[inline(always)]
    fn compute_cells_needed(total_ciphertext_cells: usize) -> usize {
        (4 /* number of cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (12 * u8) */
            + 12 /* the length of the AES-256 nonce (12 * u8) */
            + total_ciphertext_cells)
            * 2 /* 2 subcells per cell */
    }

    /// The internal implementation of the decoding algorithm.
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when decrypting the information.
    /// * `encoded_img_path` - The path to the modified image.
    ///
    fn decode_internal(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
    ) -> Result<Vec<u8>> {
        let ref_image = StegaV3::load_image(original_img_path, true)?;
        let enc_image = StegaV3::load_image(encoded_img_path, true)?;

        // The reference and encoded images must have the same dimensions.
        if enc_image.dimensions() != ref_image.dimensions() {
            return Err(Error::ImageDimensionsMismatch);
        }

        // Generate the composite key from the hash of the original
        //   file and the key.
        let mut composite_key = StegaV3::generate_composite_key(original_img_path, key)?;

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&enc_image, &composite_key);

        // This will hold all of the decoded data.
        let mut data = DataDecoder::new(8);

        // Read the first 4 XOR encoded bytes from the image.
        // This is done manually to avoid decoding the entire image.
        for i in 0..8 {
            let val = self.read_u8_by_index(&ref_image, &enc_image, i);
            data.push_u8(val);
        }

        // Decode the XOR-encoded values back into their original values.
        data.decode();

        // The next set of bytes should be the total number of cipher-text bytes
        //   cells that have been encoded.
        let total_ciphertext_cells = data.pop_u32();

        // Now we can calculate how many bytes we need to read.
        let total_cells_needed = StegaV3::compute_cells_needed(total_ciphertext_cells as usize);

        /*
          In total we will never store more than 0xFFFFFFFF bytes of data.
          This is done to keep the total number of cells below the maximum
            possible value for an unsigned 32-bit integer.
        */
        if total_cells_needed > u32::MAX as usize {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to decode the data?
        let total_cells = StegaV3::get_total_cells(&enc_image);
        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // Read all of the XOR-encoded bytes that are relevant for our decode.
        let mut data = DataDecoder::new(total_cells_needed);
        for i in 0..total_cells_needed {
            let val = self.read_u8_by_index(&ref_image, &enc_image, i);
            data.push_u8(val);
        }

        // Decode the XOR-encoded values.
        data.decode();

        // We do not care about this value.
        data.pop_u32();

        // Note: we can unwrap these values as we will assert if the
        //   length of the vector is not equal to the length we requested.
        // Next, we get the Argon2 salt bytes.
        let salt_bytes: [u8; 12] = data.pop_vec(12).try_into().unwrap();

        // Next, we get the AES nonce bytes.
        let nonce_bytes: [u8; 12] = data.pop_vec(12).try_into().unwrap();

        // Add the cipher-text bytes.
        let ciphertext_bytes = data.pop_vec(total_ciphertext_cells as usize);

        // Now we can compute the Argon2 hash.
        let mut key_bytes_full = hashers::argon2_string(
            &composite_key,
            salt_bytes,
            self.m_cost,
            self.p_cost,
            self.t_cost,
            ARGON_VER,
        )?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        /*
          Attempt to decrypt the cipher-text bytes with
            the extracted information.

          This will fail if the decryption does not yield valid data.

          This could occur for any number of reasons, including:
            * There was no information stored.
            * One or more of the files were modified.
            * The decrypted key was incorrect.
        */
        let plaintext_bytes = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(Error::DecryptionFailed);
            }
        };

        // Zero out sensitive material.
        composite_key.zeroize();
        key_bytes_full.zeroize();

        Ok(plaintext_bytes)
    }

    /// The internal implementation of the encoding algorithm.
    ///
    /// # Arguments
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when encrypting the information.
    /// * `data` - The data to be encrypted and encoded within the reference image.
    /// * `encoded_img_path` - The path that will be used to store the encoded image.
    ///
    fn encode_internal(
        &mut self,
        original_img_path: &str,
        key: String,
        data: &[u8],
        encoded_img_path: &str,
    ) -> Result<()> {
        // We don't need to hold a separate reference image instance here.
        let mut img = StegaV3::load_image(original_img_path, false)?;

        // Generate the composite key from the hash of the original file and the key.
        let mut composite_key = StegaV3::generate_composite_key(original_img_path, key)?;

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; 12] = misc_utils::secure_random_bytes();
        let mut key_bytes_full = hashers::argon2_string(
            &composite_key,
            salt_bytes,
            M_COST,
            P_COST,
            T_COST,
            ARGON_VER,
        )?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let nonce_bytes: [u8; 12] = misc_utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // We will convert the input data byte vector into a base64 string.
        //let plaintext = misc_utils::encode_u8_slice_to_base64_str(data);
        let Ok(ct_bytes) = cipher.encrypt(nonce, data) else {
            return Err(Error::EncryptionFailed);
        };

        /*
          4 cells for the total number of stored cipher-text cells,
            the salt, the nonce and the cipher-text itself.

          This value must be doubled as we need 2 cells per byte:
            one for the XOR encoded byte and one for the XOR byte.

          This value must be held within a 64-bit value to prevent integer
            overflow from occurring in the when running this on a
            32-bit architecture.

          Note: a cell represents the space in which a byte of data
            can be encoded.
        */
        let total_ct_cells = ct_bytes.len();
        let total_cells_needed = StegaV3::compute_cells_needed(total_ct_cells);

        // In total we can never store more than 0xFFFFFFFF bytes of data to
        //   ensure that the values of usize never exceeds the maximum value
        //   of the u32 type.
        if total_cells_needed > u32::MAX as usize {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to encode the data?
        let total_cells = StegaV3::get_total_cells(&img);
        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // This will hold all of the data to be encoded.
        let mut data = DataEncoder::new(total_cells);

        // Add the total number of cipher-text cells needed.
        data.push_u32(total_ct_cells as u32);

        // Add the Argon2 salt bytes.
        data.push_u8_slice(&salt_bytes);

        // Add the AES nonce bytes.
        data.push_u8_slice(&nonce_bytes);

        // Add the cipher-text bytes.
        data.push_u8_slice(&ct_bytes);

        // Fill all of the unused cells with junk random data.
        if self.noise_layer {
            data.fill_empty_bytes();
        }

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&img, &composite_key);

        composite_key.zeroize();
        key_bytes_full.zeroize();

        // Iterate over each byte of data to be encoded.
        for (i, byte) in data.bytes.iter().enumerate() {
            self.write_u8_by_data_index(&mut img, byte, i);
        }

        if !self.output_files {
            return Ok(());
        }

        // Attempt to save the modified image.
        if let Err(e) = img.save(encoded_img_path) {
            Err(Error::ImageSaving(e.to_string()))
        } else {
            Ok(())
        }
    }

    /// Gets the cell index that will hold the specified data index.
    ///
    /// # Arguments
    ///
    /// * `data_index` - The data index to be checked.
    ///
    /// `Note:` this method will panic if the data cell is not present in the map.
    /// In practice this should never occur.
    ///
    #[inline]
    fn get_data_cell_index(&self, data_index: &usize) -> usize {
        self.data_cell_vec[*data_index]
    }

    /// Calculate the total number of cells available in a given image.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    #[inline]
    fn get_total_cells(img: &ImageWrapper) -> usize {
        // 1 byte is 8 bits in length.
        // We can store 1 bit per channel.
        (img.get_total_channels() / 8) as usize
    }

    /// Generate a composite key from the hash of the original file and the plaintext key.
    ///
    /// # Arguments
    ///
    /// * `original_path` - The path to the original image file.
    /// * `key` - The plaintext key.
    ///
    #[inline]
    pub fn generate_composite_key(original_path: &str, key: String) -> Result<Vec<u8>> {
        /*
          The key for the encryption is the SHA3-512 hash of the input image file
            combined with the plaintext key and the version number.

          It intentional that we take ownership of the key as it will be
            cleared from memory when this function exits.
        */
        let file_hash_bytes = hashers::sha3_512_file(original_path)?;

        // Pre-allocate with known size for performance
        let mut composite_key = Vec::with_capacity(file_hash_bytes.len() + key.len() + 1);
        composite_key.extend_from_slice(&file_hash_bytes);
        composite_key.extend_from_slice(key.as_bytes());
        composite_key.push(CODED_VERSION);

        Ok(composite_key)
    }

    /// Loads an image from file and validates that the image is suitable for steganography.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    /// * `read_only` - The whether the image should be opened in a read-only state.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a [`ImageWrapper`] if the image was successfully loaded and if the image is suitable for steganography.
    ///
    /// Otherwise an error will be returned.
    ///
    fn load_image(file_path: &str, read_only: bool) -> Result<ImageWrapper> {
        let img = ImageWrapper::load_from_file(file_path, read_only)?;

        // Validate if the image file can be used.
        StegaV3::validate_image(&img)?;

        Ok(img)
    }

    /// Read a byte of encoded data, starting at a specified index.
    ///
    /// # Arguments
    ///
    /// * `ref_img` - A reference to the [`ImageWrapper`] that holds the reference image.
    /// * `enc_img` - A reference to the [`ImageWrapper`] that holds the encoded image.
    /// * `cell_start` - The index from which the encoded data should be read.
    ///
    /// `Note:` this method will read 8 channels worth of data, starting at the specified index.
    ///
    #[inline]
    fn read_u8(&self, ref_img: &ImageWrapper, enc_img: &ImageWrapper, cell_start: usize) -> u8 {
        // Extract the bytes representing the pixel channels from the images.
        let rb = ref_img.get_subcells_from_index(cell_start, 2);
        let eb = enc_img.get_subcells_from_index(cell_start, 2);

        // Load 8 bytes and compute XOR mask.
        (0..8).fold(0u8, |acc, i| acc | (((rb[i] != eb[i]) as u8) << i))
    }

    /// Read a byte of encoded data for a specified data index.
    ///
    /// # Arguments
    ///
    /// * `ref_img` - A reference to the [`ImageWrapper`] that holds the reference image.
    /// * `enc_img` - A reference to the [`ImageWrapper`] that holds the encoded image.
    /// * `data_index` - The index of the data byte to be read.
    ///
    /// `Note:` this method will read 8 channels worth of data, starting at the specified index.
    ///
    #[inline]
    fn read_u8_by_index(
        &self,
        ref_img: &ImageWrapper,
        enc_img: &ImageWrapper,
        data_index: usize,
    ) -> u8 {
        // We need to look up the cell to which this byte of data
        //   will be encoded within the image.
        let start_index = self.get_data_cell_index(&data_index) * 2;

        // Finally we can decode and read a byte of data from the cell.
        self.read_u8(ref_img, enc_img, start_index)
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    fn validate_image(img: &ImageWrapper) -> Result<()> {
        // We only support PNG files.
        if img.get_image_format() != image::ImageFormat::Png {
            return Err(Error::ImageTypeInvalid);
        }

        // The total number of channels must be divisible by 8.
        // This will ensure that we can always encode a given byte of data.
        if img.get_total_channels() % 8 != 0 {
            return Err(Error::ImageDimensionsInvalid);
        }

        Ok(())
    }

    /// Encode the specified value into the pixels within a given cell.
    ///
    /// # Arguments
    ///
    /// * `img` - A mutable reference to the [`ImageWrapper`] in which the data should be encoded.
    /// * `data` - The byte value to be encoded.
    /// * `cell_start` - The index of the first pixel of the cell into which the data will be encoded.
    ///
    #[inline]
    fn write_u8(&mut self, img: &mut ImageWrapper, data: &u8, cell_start: usize) {
        let bytes = img.get_subcells_from_index_mut(cell_start, 2);

        let mut rand_bits: u8 = self.position_rng.random();

        for i in 0..8 {
            if (data >> i) & 1 == 0 {
                continue;
            }

            let b = &mut bytes[i];
            let v = *b;

            // One random bit from our random bit pool.
            let r = rand_bits & 1;
            rand_bits >>= 1;
            let delta = r.wrapping_mul(2).wrapping_sub(1);

            // Apply the delta.
            let mut out = v.wrapping_add(delta);

            // Handle wrap cases.
            // v == 0   && delta == 255 → out == 255 - force to 1.
            // v == 255 && delta == 1   → out == 0   - force to 254.
            let wrapped_down = (v == 0) as u8 & (delta == 255) as u8;
            let wrapped_up = (v == 255) as u8 & (delta == 1) as u8;

            out = out
                .wrapping_add(wrapped_down) // 255 → 0
                .wrapping_add(wrapped_down) // 0 → 1
                .wrapping_sub(wrapped_up) // 0 → 255
                .wrapping_sub(wrapped_up); // 255 → 254

            *b = out;
        }
    }

    /// Write a byte of data into a specified cell within the image.
    ///
    /// # Arguments
    ///
    /// * `img` - A mutable reference to the [`ImageWrapper`] in which the data should be encoded.
    /// * `data` - The byte value to be written to the image.
    /// * `data_index` - The index of the data byte to be written.
    ///
    #[inline]
    fn write_u8_by_data_index(&mut self, img: &mut ImageWrapper, data: &u8, data_index: usize) {
        let start_index = self.get_data_cell_index(&data_index) * 2;
        self.write_u8(img, data, start_index);
    }
}

impl Codec for StegaV3 {
    fn encode(
        &mut self,
        original_img_path: &str,
        key: String,
        plaintext: &str,
        encoded_img_path: &str,
    ) -> Result<()> {
        self.encode_internal(
            original_img_path,
            key,
            plaintext.as_bytes(),
            encoded_img_path,
        )
    }

    fn encode_file(
        &mut self,
        original_img_path: &str,
        key: String,
        input_file_path: &str,
        encoded_img_path: &str,
    ) -> Result<()> {
        if !file_utils::path_exists(input_file_path) {
            return Err(Error::PathInvalid);
        }

        // Convert the file into a byte vector.
        let bytes = file_utils::read_file_to_u8_vec(input_file_path)?;

        // Encode the information into the target image.
        self.encode_internal(original_img_path, key, &bytes, encoded_img_path)
    }

    fn decode(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
    ) -> Result<String> {
        // Decode the data to yield a base64 string.
        let bytes = self.decode_internal(original_img_path, key, encoded_img_path)?;

        // Convert the raw bytes back into a string. This is done lossy
        //   to ensure that any invalid sequences are handled.
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn decode_file(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
        output_file_path: &str,
    ) -> Result<()> {
        // First, we need to extract the information from the target image.
        let bytes = self.decode_internal(original_img_path, key, encoded_img_path)?;

        // Write the raw bytes directly to the output file.
        if self.output_files {
            file_utils::write_u8_slice_to_file(output_file_path, &bytes)
        } else {
            Ok(())
        }
    }

    fn set_application_name(&mut self, _name: String) {}

    fn set_config_state(&mut self, config: Config, state: bool) {
        match config {
            Config::NoiseLayer => {
                self.noise_layer = state;
            }
            Config::Verbose => {
                self.logger.enable_verbose_mode();
            }
            Config::OutputFiles => {
                self.output_files = state;
            }
            Config::Locker => {
                self.logger
                    .log("locker file usage is not supported for this codec.");
            }
            Config::ReadOnce => {
                self.logger
                    .log("read-once functionality is not supported for this codec.");
            }
            Config::SkipVersionChecks => {
                self.logger
                    .log("skipping version checks is not supported for this codec.");
            }
            Config::TCost(_) => todo!(),
            Config::PCost(_) => todo!(),
            Config::MCost(_) => todo!(),
        }
    }
}

impl Default for StegaV3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StegaV3 {
    fn drop(&mut self) {}
}

#[cfg(test)]
mod tests_encode_decode {
    use rand::SeedableRng;
    use rand_xoshiro::Xoshiro512PlusPlus;

    use crate::{
        codecs::codec::Codec,
        hashers,
        utilities::{file_utils, test_utils::*},
    };

    use super::StegaV3;

    // The generic key used for encoding text.
    const KEY: &str = "ElPsyKongroo";
    // The generic text used to text encoding and decoding.
    const TEXT: &str = "3.1415926535";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["encoding_decoding_v3"];

    /// Create a StegaV3 instance.
    ///
    /// `Note:` we will attempt to clear the locker file upon exit by default.
    ///
    fn create_instance() -> StegaV3 {
        use crate::logger::Logger;

        // Return a new StegaV3 instance.
        StegaV3 {
            data_cell_vec: Vec::new(),
            noise_layer: false, // We do not need this here.
            output_files: true,
            logger: Logger::new(false),
            position_rng: Xoshiro512PlusPlus::from_os_rng(),
            t_cost: super::T_COST,
            p_cost: super::P_COST,
            m_cost: super::M_COST,
        }
    }

    #[test]
    fn test_composite_string_generation() {
        let tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("text-file.txt");
        let key = StegaV3::generate_composite_key(&input_path, KEY.to_string())
            .expect("failed to generate a composite key");
        let expected_key = vec![
            71, 134, 114, 66, 180, 168, 138, 97, 112, 83, 231, 160, 178, 184, 119, 26, 45, 123, 79,
            45, 101, 151, 174, 222, 6, 108, 69, 242, 66, 76, 249, 51, 234, 135, 206, 72, 147, 153,
            66, 173, 164, 26, 176, 234, 219, 123, 11, 70, 99, 186, 81, 104, 126, 3, 108, 20, 174,
            84, 225, 202, 192, 54, 10, 5, 69, 108, 80, 115, 121, 75, 111, 110, 103, 114, 111, 111,
            3,
        ];

        assert_eq!(
            key, expected_key,
            "composite key does not match expected key"
        );
    }

    #[test]
    fn test_encode_string() {
        /*
          This might seem like a pointless test, but while refactoring
            I accidentally changed the way that they keys were generated,
            which prevented the decoding of any files created prior to that change.
          This will ensure backwards compatibility is maintained within a version.
        */
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode(&ref_path, KEY.to_string(), TEXT, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk."
        );

        // Did we successfully encode the string?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("text-file.txt");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode_file(&ref_path, KEY.to_string(), &input_file_path, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk"
        );

        // Did we successfully encode the file?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file_binary() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("binary-file.bin");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode_file(&ref_path, KEY.to_string(), &input_file_path, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk."
        );

        // Did we successfully encode the file?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_roundtrip() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

        // Attempt to decode the string.
        let result = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode the data");

        assert_eq!(result, TEXT, "failed to decode the data");
    }

    #[test]
    fn test_roundtrip_fail() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

        // Sneakily manipulate the encoded file to ensure that the decode will fail.
        let mut img =
            StegaV3::load_image(&enc_path, false).expect("failed to load the encoded image");

        // Flip a bit in the first channel of the first cell.
        img.get_subcells_from_index_mut(0, 2)[0] ^= 1;
        img.save(&enc_path)
            .expect("failed to save the manipulated image");

        // Attempt to decode the string.
        let result = stega.decode(&ref_path, KEY.to_string(), &enc_path);

        assert!(result.is_err(), "successfully to decoded the data");
    }

    #[test]
    fn test_roundtrip_fail_different_argon_params() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

        // Modify the Argon2 parameters to ensure that the decode will fail.
        stega.t_cost += 1;

        // Attempt to decode the string.
        let result = stega.decode(&ref_path, KEY.to_string(), &enc_path);

        assert!(result.is_err(), "successfully to decoded the data");
    }

    #[test]
    #[should_panic]
    fn test_decode_fixed_string_wrong_version() {
        let tu = TestUtils::new(&["encoding_decoding_v1"]);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        let mut stega = create_instance();

        let _ = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode string");
    }

    #[test]
    fn test_decode_string() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        let mut stega = create_instance();

        let r = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode string");

        // Did we successfully decode the string?
        assert_eq!(r, TEXT, "decrypted information does not match input");
    }

    #[test]
    fn test_decode_string_invalid_key() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        let mut stega = create_instance();

        let r = stega.decode(&ref_path, "A".to_string(), &enc_path);

        // Did we successfully decode the string?
        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_string_wrong_ref_image() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-invalid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        // The key is valid but the reference image is not.
        let mut stega = create_instance();

        let r = stega.decode(&ref_path, KEY.to_string(), &enc_path);

        // Did we successfully decode the string?
        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_fixed_file() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-file-text.png");
        let original_file_path = tu.get_in_file("text-file.txt");
        let output_file_path = tu.get_out_file("txt", true);

        // Attempt to decode the file.
        let mut stega = create_instance();

        stega
            .decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path)
            .expect("failed to decode string");

        // Did we successfully decode a file?
        assert!(
            file_utils::path_exists(&output_file_path),
            "file not written to disk."
        );

        // Create a hash of the original and new file. If these hashes match
        // then we can be confident that the files are the same.
        let hash_original = hashers::sha3_512_file(&original_file_path);
        let hash_new = hashers::sha3_512_file(&output_file_path);

        assert_eq!(
            hash_original, hash_new,
            "decoded file is not the same as the original"
        );
    }

    #[test]
    fn test_decode_file_invalid_key() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-file-text.png");
        let output_file_path = tu.get_out_file("png", true);

        // Attempt to decode the file.
        let mut stega = create_instance();

        let r = stega.decode_file(&ref_path, "A".to_string(), &enc_path, &output_file_path);

        // Did we successfully decode the string?
        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_file_wrong_ref_image() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-invalid.png");
        let enc_path = tu.get_in_file("encoded-file-text.png");
        let output_file_path = tu.get_out_file("png", true);

        // Attempt to decode the file.
        let mut stega = create_instance();

        let r = stega.decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path);

        // Did we successfully decode the string?
        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_fixed_file_binary() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-file-binary.png");
        let original_file_path = tu.get_in_file("binary-file.bin");
        let output_file_path = tu.get_out_file("bin", true);

        // Attempt to decode the file.
        let mut stega = create_instance();

        stega
            .decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path)
            .expect("failed to decode string");

        // Did we successfully decode a file?
        assert!(
            file_utils::path_exists(&output_file_path),
            "file not written to disk."
        );

        // Create a hash of the original and new file. If these hashes match then we
        // can be confident that the files are the same.
        assert_eq!(
            hashers::sha3_512_file(&original_file_path),
            hashers::sha3_512_file(&output_file_path),
            "decoded file is not the same as the original"
        );
    }

    #[test]
    fn test_roundtrip_string_invalid_sequences() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        let invalid_utf8 = unsafe { String::from_utf8_unchecked(vec![65, 159, 146, 150, 65]) };

        // Attempt to encode the file.
        let mut stega = create_instance();

        let r = stega.encode(&ref_path, KEY.to_string(), &invalid_utf8, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk"
        );

        // Did we successfully encode the string?
        assert_eq!(r, Ok(()), "failed to encode data into image file");

        // Now we will attempt to decode the string.
        let str = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode string");

        // Did we successfully decode the string?
        // Any invalid UTF-8 sequences should have been removed
        // during the decode cycle.
        assert_eq!(
            str, "A���A",
            "invalid sequences not removed during encode-decode cycle"
        );
    }
}

#[cfg(test)]
mod tests_encryption_decryption {
    use crate::{
        error::{Error, Result},
        utilities::test_utils::TestUtils,
    };

    use super::StegaV3;

    /// The sub directory to the test files.
    /// NOTE - these are compatible with v1, so there is no need for separate ones.
    const BASE: [&str; 1] = ["loading_and_validation"];

    struct TestEntry {
        pub file: String,
        pub expected_result: Result<()>,
        pub fail_message: String,
    }

    impl TestEntry {
        fn new(file: &str, expected_result: Result<()>, fail_message: &str) -> Self {
            Self {
                file: file.to_string(),
                expected_result,
                fail_message: fail_message.to_string(),
            }
        }

        fn fail_message(&self) -> String {
            let expected_str = match self.expected_result.clone() {
                Ok(_) => "pass".to_string(),
                Err(e) => "error = ".to_string() + &e.to_string(),
            };

            format!(
                "File: {} expected {}. Message = {}",
                self.file, expected_str, self.fail_message
            )
        }
    }

    #[test]
    fn image_loading_and_validation() {
        let tests = [
            TestEntry::new(
                "10x10-rbg.png",
                Err(Error::ImageDimensionsInvalid),
                "file type is valid, channels % 8 != 0",
            ),
            TestEntry::new(
                "10x10-rbga.png",
                Ok(()),
                "file type is valid, channels % 8 == 0",
            ),
            TestEntry::new(
                "missing-file.png",
                Err(Error::PathInvalid),
                "file is missing and therefore cannot be loaded",
            ),
        ];

        let tu = TestUtils::new(&BASE);
        for test in tests {
            let path = tu.get_in_file_no_verify(&test.file);
            let result = match StegaV3::load_image(&path, true) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            };

            assert_eq!(result, test.expected_result, "{}", test.fail_message());
        }
    }
}
