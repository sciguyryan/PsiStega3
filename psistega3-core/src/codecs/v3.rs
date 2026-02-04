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

use super::codec::Config;

/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const DEFAULT_T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const DEFAULT_P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const DEFAULT_M_COST: u32 = 65_536;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VERSION: argon2::Version = argon2::Version::V0x13;
/// The version of this codec.
const CODED_VERSION: u8 = 0x3;
/// The salt for the file component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const FILE_SALT: [u8; 64] = [
    2, 231, 192, 211, 210, 144, 152, 191, 241, 102, 139, 0, 159, 75, 168, 103, 219, 177, 8, 106,
    136, 252, 52, 247, 129, 228, 66, 53, 193, 108, 126, 11, 232, 34, 41, 150, 24, 42, 165, 221,
    240, 234, 17, 190, 107, 198, 157, 188, 74, 207, 105, 151, 176, 194, 222, 145, 14, 16, 125, 27,
    95, 100, 67, 62,
];
/// The salt for the user-provided key component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const KEY_SALT: [u8; 64] = [
    228, 243, 149, 35, 126, 159, 77, 192, 204, 207, 132, 83, 103, 218, 75, 248, 139, 76, 28, 221,
    179, 247, 189, 196, 198, 18, 118, 122, 157, 86, 231, 20, 96, 53, 136, 153, 140, 238, 52, 93,
    137, 91, 32, 239, 133, 17, 227, 129, 219, 121, 94, 116, 188, 255, 214, 48, 110, 104, 25, 70,
    85, 33, 73, 176,
];
/// The salt for the version key component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const VERSION_SALT: [u8; 64] = [
    247, 63, 225, 218, 95, 4, 179, 80, 23, 173, 189, 157, 201, 109, 217, 83, 71, 129, 87, 37, 118,
    26, 206, 234, 113, 17, 5, 223, 10, 119, 31, 34, 208, 41, 160, 74, 16, 27, 214, 180, 75, 182,
    40, 53, 175, 199, 197, 9, 111, 186, 61, 94, 104, 150, 185, 120, 149, 52, 254, 82, 164, 69, 156,
    195,
];

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
    offset_bit_rng: Xoshiro512PlusPlus,
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
            offset_bit_rng: misc_utils::secure_seeded_xoroshiro512(),
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            m_cost: DEFAULT_M_COST,
        }
    }

    /// Builds a map of data indices to cell indices.
    ///
    /// # Arguments
    ///
    /// * `key` - The key bytes that should be used to seed the random number generator.
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    fn build_data_to_cell_index_map(&mut self, img: &ImageWrapper, key: &[u8]) {
        // It doesn't matter if we call this on reference or encoded
        //   as they will have the same value at this point.
        let total_cells = StegaV3::get_total_cells(img);

        /*
          When we can't use the Argon2 hash for the positional RNG
            as we will need the salt, which will not be available when
            initially reading the data from the file.
        */
        let mut bytes = hashers::sha3_512_bytes(key);

        // We DO NOT realistically need a cryptographically secure RNG here,
        //   so we can use a faster RNG for shuffling the cells.
        // The seed is generated from the key bytes, and we
        //   make use of mixing to ensure that all bytes influence the final seed.
        let seed: u64 = key.chunks_exact(8).fold(0, |acc, chunk| {
            acc ^ u64::from_le_bytes(chunk.try_into().unwrap())
        });
        fastrand::seed(seed);

        // Clear the key bytes from memory.
        bytes.zeroize();

        // Pre-allocate vector and map for performance.
        self.data_cell_vec = Vec::with_capacity(total_cells);
        self.data_cell_vec.extend(0..total_cells);

        // Randomise the order of the cell IDs.
        fastrand::shuffle(&mut self.data_cell_vec);
    }

    #[inline(always)]
    fn compute_cells_needed(total_ciphertext_cells: usize) -> usize {
        /*
          4 cells for the total number of stored cipher-text cells,
            the salt, the nonce and the cipher-text itself.

          This value must be held within a 64-bit value to prevent integer
            overflow from occurring in the when running this on a
            32-bit architecture.

          Note: a cell represents the space in which a byte of data
            can be encoded.
        */

        4 /* number of cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (12 * u8) */
            + 12 /* the length of the AES-256 nonce (12 * u8) */
            + total_ciphertext_cells
    }

    /// The internal implementation of the decoding algorithm.
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when decrypting the information.
    /// * `encoded_img_path` - The path to the modified image.
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

        // Generate the composite key from the hash of the original file and the key.
        let mut composite_key = StegaV3::generate_composite_key(original_img_path, key)?;

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&enc_image, &composite_key);

        // Read the first 4 encoded bytes from the image.
        // This is done manually to avoid decoding the entire image.
        let total_ciphertext_cells_bytes = [
            self.read_u8_by_index(&ref_image, &enc_image, 0),
            self.read_u8_by_index(&ref_image, &enc_image, 1),
            self.read_u8_by_index(&ref_image, &enc_image, 2),
            self.read_u8_by_index(&ref_image, &enc_image, 3),
        ];

        // The next set of bytes should be the total number of cipher-text bytes
        //   cells that have been encoded.
        let total_ciphertext_cells = u32::from_le_bytes(total_ciphertext_cells_bytes);

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

        // We can skip the first four bytes as we have already read them, above.
        // We could make a smaller array here, but we can save ourselves the
        // extra operations, at the cost of a few more bytes of reserved memory... which is fine.
        // But remember... all of these offsets are four less than the original due to the skipping.
        let mut data = Vec::with_capacity(total_cells_needed);
        for i in 4..total_cells_needed {
            data.push(self.read_u8_by_index(&ref_image, &enc_image, i));
        }

        // Next, we get the Argon2 salt bytes.
        let salt_bytes: [u8; 12] = data[0..12].try_into().unwrap();

        // Next, we get the AES nonce bytes.
        let nonce_bytes: [u8; 12] = data[12..24].try_into().unwrap();

        // Add the cipher-text bytes.
        let ciphertext_bytes = &data[24..];

        // Now we can compute the Argon2 hash.
        let mut key_bytes_full = hashers::argon2_string(
            &composite_key,
            salt_bytes,
            self.m_cost,
            self.p_cost,
            self.t_cost,
            ARGON_VERSION,
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
            self.m_cost,
            self.p_cost,
            self.t_cost,
            ARGON_VERSION,
        )?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let nonce_bytes: [u8; 12] = misc_utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // We will convert the input data byte vector into a base64 string.
        let Ok(ct_bytes) = cipher.encrypt(nonce, data) else {
            return Err(Error::EncryptionFailed);
        };

        let total_ciphertext_cells = ct_bytes.len();
        let total_cells_needed = StegaV3::compute_cells_needed(total_ciphertext_cells);

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

        let capacity = if self.noise_layer {
            total_cells
        } else {
            total_cells_needed
        };

        // This will hold all of the data to be encoded.
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(&(total_ciphertext_cells as u32).to_le_bytes());
        data.extend_from_slice(&salt_bytes);
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&ct_bytes);

        // Fill all of the unused cells with junk random data, if needed.
        if self.noise_layer {
            data.extend_from_slice(&StegaV3::generate_junk_bytes(data.capacity() - data.len()));
        }

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&img, &composite_key);

        composite_key.zeroize();
        key_bytes_full.zeroize();

        // Iterate over each byte of data to be encoded.
        for (i, byte) in data.iter().enumerate() {
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
    #[inline]
    fn get_data_cell_index(&self, data_index: &usize) -> usize {
        self.data_cell_vec[*data_index] * 2
    }

    /// Calculate the total number of cells available in a given image.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
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
    #[inline]
    pub fn generate_composite_key(original_path: &str, key: String) -> Result<Vec<u8>> {
        let mut file_data = hashers::sha3_512_file(original_path)?;
        file_data.extend_from_slice(&FILE_SALT);
        let file_hash = hashers::sha3_512_bytes(&file_data);

        let mut key_bytes = key.into_bytes();
        key_bytes.extend_from_slice(&KEY_SALT);
        let key_hash = hashers::sha3_512_bytes(&key_bytes);

        let mut version_data = vec![CODED_VERSION];
        version_data.extend_from_slice(&VERSION_SALT);
        let version_hash = hashers::sha3_512_bytes(&version_data);

        // Combine the component hashes and hash the final composite key.
        let mut combined =
            Vec::with_capacity(file_hash.len() + key_hash.len() + version_hash.len());
        combined.extend_from_slice(&file_hash);
        combined.extend_from_slice(&key_hash);
        combined.extend_from_slice(&version_hash);

        Ok(hashers::sha3_512_bytes(&combined))
    }

    /// Generate junk padding data.
    #[inline]
    pub fn generate_junk_bytes(needed: usize) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::with_capacity(needed);

        // We do not need to worry about being cryptographically secure here.
        // This is just junk data to fill the empty cells.
        fastrand::fill(&mut vec[..]);

        vec
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
    #[inline]
    fn read_u8(&self, ref_img: &ImageWrapper, enc_img: &ImageWrapper, cell_start: usize) -> u8 {
        // Extract the bytes representing the pixel channels from the images.
        let rb = ref_img.get_subcells_from_index(cell_start, 2);
        let eb = enc_img.get_subcells_from_index(cell_start, 2);

        // Load 8 bytes and rebuild our u8 value.
        let mut out = 0u8;

        out |= (((rb[0] ^ eb[0]) != 0) as u8) << 0;
        out |= (((rb[1] ^ eb[1]) != 0) as u8) << 1;
        out |= (((rb[2] ^ eb[2]) != 0) as u8) << 2;
        out |= (((rb[3] ^ eb[3]) != 0) as u8) << 3;
        out |= (((rb[4] ^ eb[4]) != 0) as u8) << 4;
        out |= (((rb[5] ^ eb[5]) != 0) as u8) << 5;
        out |= (((rb[6] ^ eb[6]) != 0) as u8) << 6;
        out |= (((rb[7] ^ eb[7]) != 0) as u8) << 7;

        out
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
    #[inline]
    fn read_u8_by_index(
        &self,
        ref_img: &ImageWrapper,
        enc_img: &ImageWrapper,
        data_index: usize,
    ) -> u8 {
        // We need to look up the cell to which this byte of data
        //   will be encoded within the image.
        let start_index = self.get_data_cell_index(&data_index);

        // Finally we can decode and read a byte of data from the cell.
        self.read_u8(ref_img, enc_img, start_index)
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
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
    #[inline]
    fn write_u8(&mut self, img: &mut ImageWrapper, data: &u8, cell_start: usize) {
        let bytes = img.get_subcells_from_index_mut(cell_start, 2);

        let mut rand_bits: u64 = self.offset_bit_rng.random();

        let bytes = &mut bytes[..8];
        for (i, b) in bytes.iter_mut().enumerate() {
            if (data >> i) & 1 == 0 {
                continue;
            }

            let v = *b;

            // One random bit from our random bit pool.
            let r = (rand_bits & 1) as u8;
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
        let start_index = self.get_data_cell_index(&data_index);
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
            Config::TCost(t) => {
                self.t_cost = t;
            }
            Config::PCost(p) => {
                self.p_cost = p;
            }
            Config::MCost(m) => {
                self.m_cost = m;
            }
        }
    }
}

impl Default for StegaV3 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests_encode_decode {
    use crate::{
        codecs::codec::Codec,
        hashers,
        utilities::{file_utils, misc_utils, test_utils::*},
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
    fn create_instance() -> StegaV3 {
        use crate::logger::Logger;

        // Return a new StegaV3 instance.
        StegaV3 {
            data_cell_vec: Vec::new(),
            noise_layer: false, // We do not need this here.
            output_files: true,
            logger: Logger::new(false),
            offset_bit_rng: misc_utils::secure_seeded_xoroshiro512(),
            t_cost: super::DEFAULT_T_COST,
            p_cost: super::DEFAULT_P_COST,
            m_cost: super::DEFAULT_M_COST,
        }
    }

    #[test]
    fn test_composite_string_generation() {
        let tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("text-file.txt");
        let key = StegaV3::generate_composite_key(&input_path, KEY.to_string())
            .expect("failed to generate a composite key");

        let expected_key = vec![
            201, 193, 197, 83, 21, 48, 205, 192, 213, 80, 179, 253, 65, 255, 18, 148, 86, 20, 37,
            201, 243, 76, 36, 43, 208, 35, 46, 200, 81, 80, 120, 23, 88, 120, 237, 194, 17, 220,
            185, 94, 95, 89, 153, 55, 134, 6, 88, 108, 252, 126, 38, 19, 36, 44, 136, 184, 65, 61,
            21, 187, 151, 115, 213, 145,
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
