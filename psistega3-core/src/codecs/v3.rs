use crate::{
    codecs::codec::Codec,
    error::{Error, Result},
    hashers,
    image_wrapper::ImageWrapper,
    logger::Logger,
    utilities::*,
};

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use image::ImageFormat;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::convert::TryInto;
use zeroize::Zeroizing;

use super::codec::{ConfigFlags, ConfigParams};

/// The version of this codec.
const CODED_VERSION: u8 = 0x3;
/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const DEFAULT_T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const DEFAULT_P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const DEFAULT_M_COST: u32 = 131_072;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VERSION: argon2::Version = argon2::Version::V0x13;
/// The domain separator for the file component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const FILE_DOMAIN_SEPARATOR: [u8; 64] = [
    2, 231, 192, 211, 210, 144, 152, 191, 241, 102, 139, 0, 159, 75, 168, 103, 219, 177, 8, 106,
    136, 252, 52, 247, 129, 228, 66, 53, 193, 108, 126, 11, 232, 34, 41, 150, 24, 42, 165, 221,
    240, 234, 17, 190, 107, 198, 157, 188, 74, 207, 105, 151, 176, 194, 222, 145, 14, 16, 125, 27,
    95, 100, 67, 62,
];
/// The domain separator for the user-provided key component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const KEY_DOMAIN_SEPARATOR: [u8; 64] = [
    228, 243, 149, 35, 126, 159, 77, 192, 204, 207, 132, 83, 103, 218, 75, 248, 139, 76, 28, 221,
    179, 247, 189, 196, 198, 18, 118, 122, 157, 86, 231, 20, 96, 53, 136, 153, 140, 238, 52, 93,
    137, 91, 32, 239, 133, 17, 227, 129, 219, 121, 94, 116, 188, 255, 214, 48, 110, 104, 25, 70,
    85, 33, 73, 176,
];
/// The domain separator for the version key component of the composite key.
/// `Note:` It should be changed with new versions of the algorithm.
const VERSION_DOMAIN_SEPARATOR: [u8; 64] = [
    247, 63, 225, 218, 95, 4, 179, 80, 23, 173, 189, 157, 201, 109, 217, 83, 71, 129, 87, 37, 118,
    26, 206, 234, 113, 17, 5, 223, 10, 119, 31, 34, 208, 41, 160, 74, 16, 27, 214, 180, 75, 182,
    40, 53, 175, 199, 197, 9, 111, 186, 61, 94, 104, 150, 185, 120, 149, 52, 254, 82, 164, 69, 156,
    195,
];
/// The size of the Argon2 salt, in bytes.
const SALT_SIZE: usize = 32;
/// The size of the AES nonce, in bytes.
const NONCE_SIZE: usize = 12;
/// The size of the ciphertext byte counter, in bytes.
///
/// By default, this is an unsigned 32-bit integer, and is hence 4 bytes in size.
const CIPHERTEXT_BYTE_COUNT_SIZE: usize = 4;
/// The maximum size of the data that can be encoded, in bytes.
const ENCODE_DATA_SIZE_CAP: u64 = 250 * 1024; // 250 KiB
/// Should compression and decompression be applied to the encoded data?
const USE_COMPRESSION: bool = true;
/// Zstd compression level to be used when compressing data before encryption.
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// The struct that holds the v3 steganography algorithm.
pub struct StegaV3 {
    /// The data index to bit index map.
    data_bit_map: Vec<u32>,
    /// The logger instance for this codec.
    logger: Logger,
    // The Argon2 time cost.
    t_cost: u32,
    // The Argon2 parallel cost.
    p_cost: u32,
    // The Argon2 memory cost.
    m_cost: u32,
    /// The level of compression to be applied to the data.
    compression_level: i32,
    /// Whether or not compression/decompression should be applied to the data.
    use_compression: bool,
    /// If the resulting image file should be saved when encoding.
    output_files: bool,
}

impl StegaV3 {
    pub fn new() -> Self {
        Self {
            data_bit_map: Vec::new(),
            logger: Logger::new(false),
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            m_cost: DEFAULT_M_COST,
            use_compression: USE_COMPRESSION,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            output_files: true,
        }
    }

    /// Builds a map of data indices to bit indices.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    /// * `key` - The key bytes that should be used to seed the random number generator.
    #[inline]
    fn build_data_to_bit_index_map(&mut self, img: &ImageWrapper, key: &[u8]) {
        // The caller should have run the data through a hashing algorithm that will output
        // at least 256 bits (32 bytes) of data.
        // If more is supplied then only the first 32 bytes will be used.

        // We can use the entire key space by making use of it directly as the seed.
        let mut rng = ChaCha20Rng::from_seed(key[..32].try_into().unwrap());

        // Generate the data index to bit index map, preallocating for performance.
        let total_bits = StegaV3::get_total_storable_bits(img) as u32;
        self.data_bit_map = (0..total_bits).collect();
        self.data_bit_map.shuffle(&mut rng);
    }

    /// Compute the total number of bytes needed to encode the data.
    ///
    /// # Arguments
    ///
    /// * `total_ciphertext_bytes` - The total number of bytes that are needed to encode the cipher-text.
    ///
    /// `Note:` this will include the bytes needed to encode the salt, nonce, and total cipher-text byte count.
    #[inline(always)]
    fn compute_payload_bits(total_ciphertext_bytes: usize) -> Result<usize> {
        /*
          This value must be held within a 64-bit value to prevent integer
            overflow from occurring in the when running this on a 32-bit architecture.
        */
        let bits_needed = (CIPHERTEXT_BYTE_COUNT_SIZE as u64
            + SALT_SIZE as u64
            + NONCE_SIZE as u64
            + total_ciphertext_bytes as u64)
            * 8;
        if bits_needed < u32::MAX as u64 {
            Ok(bits_needed as usize)
        } else {
            Err(Error::DataTooLarge)
        }
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
        let composite_key =
            Zeroizing::new(StegaV3::generate_composite_key(original_img_path, key)?);

        // Build the data index to positional bit index map.
        self.build_data_to_bit_index_map(&enc_image, &composite_key[..]);

        let mut bit_counter = 0;

        // Read the first 4 encoded bytes from the image.
        // This is done manually to avoid decoding the entire image.
        let total_ciphertext_bytes_parts = [
            self.read_u8_by_index(&ref_image, &enc_image, &mut bit_counter),
            self.read_u8_by_index(&ref_image, &enc_image, &mut bit_counter),
            self.read_u8_by_index(&ref_image, &enc_image, &mut bit_counter),
            self.read_u8_by_index(&ref_image, &enc_image, &mut bit_counter),
        ];

        // The next set of bytes should be the total number of cipher-text bytes
        //   blocks that have been encoded.
        let total_ciphertext_bytes = u32::from_le_bytes(total_ciphertext_bytes_parts);

        // Now we can calculate how many bytes of data we need to read.
        let total_bits_needed = StegaV3::compute_payload_bits(total_ciphertext_bytes as usize)?;

        // Do we have enough space within the image to decode the data?
        let total_available_bits = StegaV3::get_total_storable_bits(&enc_image);
        if total_bits_needed > total_available_bits {
            return Err(Error::ImageInsufficientSpace);
        }

        // We can skip the first four bytes as we have already read them, above.
        let remaining_bytes = (total_bits_needed / 8) - CIPHERTEXT_BYTE_COUNT_SIZE;
        let mut data = Vec::with_capacity(remaining_bytes);

        for _ in 0..remaining_bytes {
            let byte = self.read_u8_by_index(&ref_image, &enc_image, &mut bit_counter);
            data.push(byte);
        }

        // Extract the salt and nonce.
        let salt_bytes: [u8; SALT_SIZE] = data[0..SALT_SIZE].try_into().unwrap();
        let nonce_bytes: [u8; NONCE_SIZE] = data[SALT_SIZE..(SALT_SIZE + NONCE_SIZE)]
            .try_into()
            .unwrap();

        // Extract the ciphertext bytes.
        let ciphertext_bytes = &data[(SALT_SIZE + NONCE_SIZE)..];

        // Now we can compute the Argon2 hash.
        let key_bytes_full = Zeroizing::new(hashers::argon2_string(
            &composite_key[..],
            &salt_bytes,
            self.m_cost,
            self.p_cost,
            self.t_cost,
            ARGON_VERSION,
        )?);

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        /*
          Attempt to decrypt the cipher-text bytes with the extracted information.

          This will fail if the decryption does not yield valid data.

          This could occur for any number of reasons, including:
            * There was no information stored.
            * One or more of the files were modified.
            * The decrypted key was incorrect.
            * The data was encoded with compression, but not decoded with compression enabled.
        */
        let decrypted_data = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(Error::DecryptionFailed),
        };

        // Decompress the data, if required.
        if self.use_compression {
            let Ok(decompressed_data) = misc_utils::decompress(&decrypted_data) else {
                return Err(Error::DecompressionFailed);
            };

            Ok(decompressed_data)
        } else {
            Ok(decrypted_data)
        }
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
        let composite_key =
            Zeroizing::new(StegaV3::generate_composite_key(original_img_path, key)?);

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; SALT_SIZE] = misc_utils::secure_random_bytes();
        let key_bytes_full = Zeroizing::new(hashers::argon2_string(
            &composite_key[..],
            &salt_bytes,
            self.m_cost,
            self.p_cost,
            self.t_cost,
            ARGON_VERSION,
        )?);

        // Build the data index to positional block index map.
        self.build_data_to_bit_index_map(&img, &composite_key[..]);

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a random nonce.
        let nonce_bytes: [u8; NONCE_SIZE] = misc_utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Compress the data, if required.
        let maybe_compressed_data = if self.use_compression {
            let Ok(compressed_data) = misc_utils::compress(data, self.compression_level) else {
                return Err(Error::CompressionFailed);
            };

            compressed_data
        } else {
            data.to_vec()
        };

        // Encrypt the data. We want to do this _after_ the compression because encrypted
        // data should appear random, and so be significantly harder to effectively compress.
        let Ok(ciphertext_bytes) = cipher.encrypt(nonce, &maybe_compressed_data[..]) else {
            return Err(Error::EncryptionFailed);
        };

        let total_ciphertext_bytes = ciphertext_bytes.len();
        let total_bits_needed = StegaV3::compute_payload_bits(total_ciphertext_bytes)?;

        // Do we have enough space within the image to encode the data?
        let total_available_bits = StegaV3::get_total_storable_bits(&img);
        if total_bits_needed > total_available_bits {
            return Err(Error::ImageInsufficientSpace);
        }

        let mut to_encode = Vec::with_capacity(total_bits_needed / 8);
        to_encode.extend_from_slice(&(total_ciphertext_bytes as u32).to_le_bytes());
        to_encode.extend_from_slice(&salt_bytes);
        to_encode.extend_from_slice(&nonce_bytes);
        to_encode.extend_from_slice(&ciphertext_bytes);

        // Iterate over each byte of data to be encoded.
        let mut bit_counter = 0;
        for byte in &to_encode {
            self.write_u8_by_data_index(&mut img, byte, &mut bit_counter);
        }

        if !self.output_files {
            return Ok(());
        }

        // Attempt to save the modified image.
        if let Err(e) = img.save_lossless(encoded_img_path) {
            Err(Error::ImageSaving(e.to_string()))
        } else {
            Ok(())
        }
    }

    /// Calculate the total number of bits available in a given image.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    #[inline]
    fn get_total_storable_bits(img: &ImageWrapper) -> usize {
        // 1 byte is 8 bits in length. We can store 1 bit per channel.
        img.get_total_channels() as usize
    }

    /// Generate a composite key from the hash of the original file and the plaintext key.
    ///
    /// # Arguments
    ///
    /// * `original_path` - The path to the original image file.
    /// * `key` - The plaintext key.
    #[inline]
    pub(crate) fn generate_composite_key(original_path: &str, key: String) -> Result<[u8; 32]> {
        let mut file_data = Zeroizing::new(hashers::sha3_512_file(original_path)?.to_vec());
        file_data.extend_from_slice(&FILE_DOMAIN_SEPARATOR);
        let file_hash = hashers::sha3_512_bytes(&file_data);

        let mut key_bytes = Zeroizing::new(key.into_bytes());
        key_bytes.extend_from_slice(&KEY_DOMAIN_SEPARATOR);
        let key_hash = hashers::sha3_512_bytes(&key_bytes);

        let mut version_data = Zeroizing::new(vec![CODED_VERSION]);
        version_data.extend_from_slice(&VERSION_DOMAIN_SEPARATOR);
        let version_hash = hashers::sha3_512_bytes(&version_data);

        // Combine the component hashes and hash the final composite key.
        let mut combined = [0u8; 64 * 3]; // 3 x SHA3-512 hashes.
        combined[..64].copy_from_slice(&file_hash);
        combined[64..128].copy_from_slice(&key_hash);
        combined[128..].copy_from_slice(&version_hash);

        // We the combined key through a 256-bit hashing function to get the final composite key.
        Ok(hashers::sha3_256_bytes(&combined))
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
    /// Otherwise an error will be returned.
    fn load_image(file_path: &str, read_only: bool) -> Result<ImageWrapper> {
        let img = ImageWrapper::load_from_file(file_path, read_only)?;
        StegaV3::validate_image(&img)?;

        Ok(img)
    }

    /// Read a byte of encoded data from the image.
    ///
    /// # Arguments
    ///
    /// * `ref_img` - A reference to the [`ImageWrapper`] that holds the reference image.
    /// * `enc_img` - A reference to the [`ImageWrapper`] that holds the encoded image.
    /// * `data_index` - The index of the data byte to be read.
    /// * `start_bit` - The starting index of the first bit to be written, which will be updated after writing.
    #[inline]
    fn read_u8_by_index(
        &self,
        ref_img: &ImageWrapper,
        enc_img: &ImageWrapper,
        start_bit: &mut usize,
    ) -> u8 {
        let mut out = 0u8;

        for i in 0..8 {
            let mapped_index = self.data_bit_map[*start_bit + i] as usize;
            let byte_index = mapped_index / 8;
            let bit_index = mapped_index % 8;
            let mask = 1u8 << bit_index;

            let ref_b = ref_img.get_channel(byte_index);
            let enc_b = enc_img.get_channel(byte_index);

            let bit = ((ref_b & mask) >> bit_index) ^ ((enc_b & mask) >> bit_index);
            out |= bit << i;
        }

        *start_bit += 8;

        out
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    fn validate_image(img: &ImageWrapper) -> Result<()> {
        if !matches!(
            img.get_image_format(),
            ImageFormat::Bmp
                | ImageFormat::Farbfeld
                | ImageFormat::Png
                | ImageFormat::Tiff
                | ImageFormat::WebP
        ) {
            return Err(Error::ImageTypeInvalid);
        }

        // The total number of channels must be divisible by 8.
        // This will ensure that we can always encode a given byte of data.
        //
        // We want to keep this here as it ensures we will always be able to safely read
        // a whole byte of data (even if it's ultimately junk) without worrying about trying to
        // read beyond the bounds of the image data.
        if img.get_total_channels() % 8 != 0 {
            return Err(Error::ImageDimensionsInvalid);
        }

        Ok(())
    }

    /// Write a byte of data into the image.
    ///
    /// # Arguments
    ///
    /// * `img` - A mutable reference to the [`ImageWrapper`] in which the data should be encoded.
    /// * `data` - The byte value to be written to the image.
    /// * `start_bit` - The starting index of the first bit to be written, which will be updated after writing.
    #[inline]
    fn write_u8_by_data_index(&mut self, img: &mut ImageWrapper, data: &u8, start_bit: &mut usize) {
        for i in 0..8 {
            let mapped_index = self.data_bit_map[*start_bit + i] as usize;
            let byte_index = mapped_index / 8;
            let bit_index = mapped_index % 8;
            let mask = 1u8 << bit_index;

            let b = img.get_channel_mut(byte_index);

            let xor_bit = ((*b & mask) >> bit_index) ^ ((data >> i) & 1);
            *b = (*b & !mask) | (xor_bit << bit_index);
        }

        *start_bit += 8;
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
        // Realistically, the limit could be higher, but I just want to prevent silly people
        // doing silly things.
        if plaintext.len() as u64 > ENCODE_DATA_SIZE_CAP {
            return Err(Error::DataTooLarge);
        }

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
        // This limit is somewhat arbitrary, but it is meant to prevent users from trying to encode
        // files that are too large.
        // Realistically, the limit could be higher, but I just want to prevent silly people
        // doing silly things.
        let size = file_utils::get_file_size(input_file_path)?;
        if size > ENCODE_DATA_SIZE_CAP {
            return Err(Error::DataTooLarge);
        }

        let bytes = file_utils::read_file_to_u8_vec(input_file_path)?;
        self.encode_internal(original_img_path, key, &bytes, encoded_img_path)
    }

    fn decode(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
    ) -> Result<String> {
        let bytes = self.decode_internal(original_img_path, key, encoded_img_path)?;
        let maybe_zstd = misc_utils::is_zstd_frame(&bytes);

        if let Ok(s) = String::from_utf8(bytes) {
            Ok(s)
        } else {
            if maybe_zstd {
                self.logger.log("Decryption failed, but a zstd frame magic header was detected at index 0 of the decoded data.");
                self.logger
                    .log("Verifying that compression is enabled when decoding may help.");
            }

            Err(Error::DecodeStringInvalid)
        }
    }

    fn decode_file(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
        output_file_path: &str,
    ) -> Result<()> {
        let bytes = self.decode_internal(original_img_path, key, encoded_img_path)?;

        if self.output_files {
            file_utils::write_u8_slice_to_file(output_file_path, &bytes)
        } else {
            Ok(())
        }
    }

    fn set_application_name(&mut self, _name: String) {}

    fn set_flag_state(&mut self, config: ConfigFlags, state: bool) {
        match config {
            ConfigFlags::NoiseLayer => {
                self.logger
                    .log("noise layer functionality is not supported for this codec.");
            }
            ConfigFlags::Verbose => {
                if state {
                    self.logger.enable_verbose_mode();
                } else {
                    self.logger.disable_verbose_mode();
                }
            }
            ConfigFlags::OutputFiles => {
                self.output_files = state;
            }
            ConfigFlags::Locker => {
                self.logger
                    .log("locker file usage is not supported for this codec.");
            }
            ConfigFlags::ReadOnce => {
                self.logger
                    .log("read-once functionality is not supported for this codec.");
            }
            ConfigFlags::SkipVersionChecks => {
                self.logger
                    .log("skipping version checks is not supported for this codec.");
            }
            ConfigFlags::UseCompression => {
                self.use_compression = state;
            }
        }
    }

    fn set_parameter(&mut self, param: ConfigParams) {
        match param {
            ConfigParams::TCost(t) => {
                self.t_cost = t;
            }
            ConfigParams::PCost(p) => {
                self.p_cost = p;
            }
            ConfigParams::MCost(m) => {
                self.m_cost = m;
            }
            ConfigParams::CompressionLevel(c) => {
                self.compression_level = c;
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
mod tests_encode_decode_v3 {
    use crate::{
        codecs::{
            codec::{Codec, ConfigFlags, ConfigParams},
            v3::DEFAULT_COMPRESSION_LEVEL,
        },
        error::Error,
        hashers,
        utilities::{file_utils, test_utils::*},
    };

    use image::{ExtendedColorType, ImageFormat};

    use super::StegaV3;

    // The generic key used for encoding text.
    const KEY: &str = "ElPsyKongroo";
    // The generic text used to text encoding and decoding.
    const TEXT: &str = "3.1415926535";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["encoding_decoding_v3"];
    /// Are we debugging?
    const DEBUG: bool = true;

    /// Create a StegaV3 instance.
    fn create_instance() -> StegaV3 {
        use crate::logger::Logger;

        // Return a new StegaV3 instance.
        StegaV3 {
            data_bit_map: Vec::new(),
            logger: Logger::new(false),
            t_cost: 1,     // Minimal defaults to speed up encoding and decoding.
            p_cost: 2,     // Minimal defaults to speed up encoding and decoding.
            m_cost: 4_000, // Minimal defaults to speed up encoding and decoding.
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            use_compression: false,
            output_files: true,
        }
    }

    #[test]
    fn test_composite_string_generation() {
        /*
          This might seem like a pointless test, but while refactoring
            I accidentally changed the way that they keys were generated,
            which prevented the decoding of any files created prior to that change.
          This will ensure backwards compatibility is maintained within a version.
        */
        let tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("text-file.txt");
        let key = StegaV3::generate_composite_key(&input_path, KEY.to_string())
            .expect("failed to generate a composite key");

        let expected_key = [
            84, 140, 159, 192, 175, 222, 217, 114, 145, 139, 69, 215, 230, 222, 10, 182, 108, 63,
            238, 13, 129, 112, 243, 117, 98, 164, 27, 185, 40, 151, 189, 174,
        ];

        assert_eq!(
            key, expected_key,
            "composite key does not match expected key"
        );
    }

    #[test]
    fn test_encode_string() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        let mut stega = create_instance();
        let r = stega.encode(&ref_path, KEY.to_string(), TEXT, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk."
        );

        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("text-file.txt");
        let enc_path = tu.get_out_file("png", true);

        let mut stega = create_instance();
        let r = stega.encode_file(&ref_path, KEY.to_string(), &input_file_path, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk"
        );

        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file_binary() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("binary-file.bin");
        let enc_path = tu.get_out_file("png", true);

        let mut stega = create_instance();
        let r = stega.encode_file(&ref_path, KEY.to_string(), &input_file_path, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk."
        );

        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_roundtrip() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        let mut stega = create_instance();

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

        let result = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode the data");

        assert_eq!(result, TEXT, "failed to decode the data");
    }

    #[test]
    fn test_roundtrip_custom_argon2_params() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        let mut stega = create_instance();

        stega.set_parameter(ConfigParams::TCost(10));
        stega.set_parameter(ConfigParams::PCost(10));
        stega.set_parameter(ConfigParams::MCost(80_000));

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

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

        let mut stega = create_instance();

        stega
            .encode(&ref_path, KEY.to_string(), TEXT, &enc_path)
            .expect("failed to encode the data");

        // Modify the Argon2 parameters, which should prevent decoding.
        stega.t_cost += 1;

        let result = stega.decode(&ref_path, KEY.to_string(), &enc_path);

        assert!(result.is_err(), "successfully to decoded the data");
    }

    #[test]
    #[should_panic]
    fn test_decode_fixed_string_wrong_version() {
        let tu = TestUtils::new(&["encoding_decoding_v2"]);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        let mut stega = create_instance();
        let _ = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode string");
    }

    #[test]
    fn test_decode_fixed_string() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        let mut stega = create_instance();

        let r = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode string");

        assert_eq!(r, TEXT, "decrypted information does not match input");
    }

    #[test]
    fn test_decode_fixed_string_invalid_key() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        let mut stega = create_instance();
        let r = stega.decode(&ref_path, "A".to_string(), &enc_path);

        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_fixed_string_marathon_all_formats() {
        let formats = [
            ImageFormat::Bmp,
            ImageFormat::Farbfeld,
            ImageFormat::Png,
            ImageFormat::Tiff,
            ImageFormat::WebP,
        ];

        let mut stega = create_instance();

        // These parameters have been tweaked to make things run faster, but they don't
        // otherwise impact the testing at all.
        stega.set_parameter(ConfigParams::TCost(1));
        stega.set_parameter(ConfigParams::PCost(1));
        stega.set_parameter(ConfigParams::MCost(4_000));

        for &format in &formats {
            for &colour_type in supported_color_types(format) {
                let colour_name = format!("{colour_type:?}").to_lowercase();
                let ext = if format != ImageFormat::Farbfeld {
                    format!("{format:?}").to_lowercase()
                } else {
                    "ff".to_string()
                };

                if DEBUG {
                    eprint!("Running test for colour_name = {colour_name}, format = {ext}...");
                }

                // Build our test instance and paths.
                let tu = TestUtils::new(&vec![BASE[0], "format_tests", &ext]);
                let ref_path = tu.get_in_file(&format!("test_{colour_name}_ref.{ext}"));
                let enc_path = tu.get_in_file(&format!("test_{colour_name}_encoded.{ext}"));

                let r = stega
                    .decode(&ref_path, KEY.to_string(), &enc_path)
                    .expect("failed to decode string");

                // Stop immediately if we fail as running further tests is pointless.
                assert_eq!(r, TEXT, "decrypted information does not match input for type {colour_name} and format {ext}");

                if DEBUG {
                    eprintln!(" PASSED!");
                }
            }
        }
    }

    fn supported_color_types(format: ImageFormat) -> &'static [ExtendedColorType] {
        match format {
            ImageFormat::Farbfeld => &[ExtendedColorType::Rgba16],
            ImageFormat::Png => &[
                ExtendedColorType::L8,
                ExtendedColorType::La8,
                ExtendedColorType::L16,
                ExtendedColorType::La16,
                ExtendedColorType::Rgb8,
                ExtendedColorType::Rgba8,
                ExtendedColorType::Rgb16,
                ExtendedColorType::Rgba16,
            ],
            ImageFormat::Tiff => &[
                ExtendedColorType::L8,
                ExtendedColorType::L16,
                ExtendedColorType::Rgb8,
                ExtendedColorType::Rgba8,
                ExtendedColorType::Rgb16,
                ExtendedColorType::Rgba16,
                ExtendedColorType::Rgb32F,
                ExtendedColorType::Rgba32F,
            ],
            ImageFormat::WebP => &[
                ExtendedColorType::L8,
                ExtendedColorType::La8,
                ExtendedColorType::Rgb8,
                ExtendedColorType::Rgba8,
            ],
            _ => &[],
        }
    }

    #[test]
    fn test_decode_fixed_string_wrong_ref_image() {
        let tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-invalid.png");
        let enc_path = tu.get_in_file("encoded-text.png");

        let mut stega = create_instance();
        let r = stega.decode(&ref_path, KEY.to_string(), &enc_path);

        assert!(
            r.is_err(),
            "successfully decrypted the information with an invalid key!"
        );
    }

    #[test]
    fn test_decode_fixed_text_file() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_in_file("encoded-file-text.png");
        let original_file_path = tu.get_in_file("text-file.txt");
        let output_file_path = tu.get_out_file("txt", true);

        let mut stega = create_instance();
        stega
            .decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path)
            .expect("failed to decode string");

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

        let mut stega = create_instance();
        let r = stega.decode_file(&ref_path, "A".to_string(), &enc_path, &output_file_path);

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

        let mut stega = create_instance();
        let r = stega.decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path);

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

        let mut stega = create_instance();
        stega
            .decode_file(&ref_path, KEY.to_string(), &enc_path, &output_file_path)
            .expect("failed to decode string");

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

        let mut stega = create_instance();
        let r = stega.encode(&ref_path, KEY.to_string(), &invalid_utf8, &enc_path);

        assert!(
            file_utils::path_exists(&enc_path),
            "file not written to disk"
        );
        assert_eq!(r, Ok(()), "failed to encode data into image file");

        let result = stega.decode(&ref_path, KEY.to_string(), &enc_path);
        assert_eq!(result, Err(Error::DecodeStringInvalid));
    }

    #[test]
    fn test_compression_roundtrip() {
        let mut tu = TestUtils::new(&BASE);

        let ref_path = tu.get_in_file("reference-valid.png");
        let enc_path = tu.get_out_file("png", true);

        // Define a lovely compressible string.
        const TEST_STRING: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let mut stega = create_instance();

        // Encode the data using compression.
        stega.set_flag_state(ConfigFlags::UseCompression, true);
        stega.set_parameter(ConfigParams::CompressionLevel(5));
        stega
            .encode(&ref_path, KEY.to_string(), TEST_STRING, &enc_path)
            .expect("failed to encode the data");

        // The data should be successfully decoded as compression is still enabled.
        let result = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode the data");
        assert_eq!(result, TEST_STRING, "failed to decode the data");

        // If we set the wrong compression level, decoding should NOT fail. Why?
        // ZSH is smart and encodes the compression level in the encoded data.
        stega.set_parameter(ConfigParams::CompressionLevel(3));

        let result_2 = stega
            .decode(&ref_path, KEY.to_string(), &enc_path)
            .expect("failed to decode the data");
        assert_eq!(
            result_2, TEST_STRING,
            "failed to decoded the data with the wrong compression level"
        );

        // Now if we disable compression, decoding should fail. Why?
        // This should yield invalid unicode data when the compressed bytes are interpreted as unicode,
        // which should lead the decoder to thinking that the decryption failed - yielding only junk data.
        stega.set_flag_state(ConfigFlags::UseCompression, false);

        let result_3 = stega.decode(&ref_path, KEY.to_string(), &enc_path);
        assert_eq!(
            result_3,
            Err(Error::DecodeStringInvalid),
            "successfully decoded the data with compression disabled ex post facto"
        );
    }
}

#[cfg(test)]
mod tests_encryption_decryption_v3 {
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
