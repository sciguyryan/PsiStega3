use crate::{
    codecs::codec::Codec,
    error::{Error, Result},
    hashers,
    image_wrapper::ImageWrapper,
    locker::Locker,
    logger::Logger,
    utilities::{png_utils::PngChunkType, *},
};

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use hashbrown::HashMap;
use rand_codec_v1::prelude::*;
use rand_xoshiro_codec_v1::Xoshiro512PlusPlus;
use std::{collections::VecDeque, convert::TryInto};

use self::misc_utils::BIT_MASKS;

use super::codec::Config;

/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const M_COST: u32 = 65536;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VER: argon2::Version = argon2::Version::V0x13;

/// The struct that holds the v1 Steganography algorithm.
pub struct StegaV1 {
    /// The application name.
    application_name: String,
    /// The data index to cell ID map.
    data_cell_map: HashMap<usize, usize>,
    /// If the noise layer should be applied to the output image.
    noise_layer: bool,
    /// If the resulting image file should be saved when encoding.
    output_files: bool,
    /// Flags for use when encoding and decoding.
    /// Bit 0 indicates that the file locker is to be used with this file.
    /// Bit 1 indicates that the file is read-once.
    /// Bits 2 to 7 are reserved for future use.
    flags: u8,
    /// The file locker instance for this codec.
    locker: Locker,
    /// The logger instance for this codec.
    logger: Logger,
}

impl StegaV1 {
    pub fn new(application_name: &str) -> Self {
        let mut application_name = application_name;
        if application_name.is_empty() {
            application_name = "PsiStega3"
        }

        let locker =
            Locker::new(application_name, "").expect("could not initialize the file locker");

        Self {
            application_name: application_name.to_string(),
            data_cell_map: HashMap::new(),
            noise_layer: true,
            output_files: true,
            flags: 0,
            locker,
            logger: Logger::new(false),
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
        let total_cells = StegaV1::get_total_cells(img);

        // Create and fill our vector with sequential values, one
        //   for each cell ID.
        let mut cell_list: Vec<usize> = (0..total_cells).collect();

        // Randomize the order of the cell IDs.
        cell_list.shuffle(&mut rng);

        // Add the randomized entries to our cell map.
        self.data_cell_map = cell_list
            .iter()
            .rev()
            .enumerate()
            .map(|(i, id)| (i, *id))
            .collect();
    }

    /// Clear the lock on a file. Only used when use_file_locker is enabled.
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn clear_file_lock(&mut self, hash: &Vec<u8>) {
        if !self.is_file_locker_enabled() {
            return;
        }

        // The decryption was successful, we can remove any file locker
        //   attempts that might be present.
        self.locker.clear_file_lock(hash);
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
    ) -> Result<String> {
        // Process the bKGD chunk data.
        // If it isn't present then we will not attempt to decode the file.
        if !self.process_bkgd_chunk(encoded_img_path) {
            return Err(Error::DecryptionFailed);
        }

        // If the file locker system is enabled then we will need to computer
        //   the SHA3-512 has of the file here.
        let mut enc_hash = vec![];
        if self.is_file_locker_enabled() {
            if let Ok(v) = hashers::sha3_512_file(encoded_img_path) {
                enc_hash = v;
            } else {
                return Err(Error::FileHashingError);
            }

            // The first thing we need to do is to check whether the file hash
            //   exists within the locker file index.
            // If it does then we need to check whether the file is already locked.
            //   if it is then we will not try to decode the file.
            if self.locker.is_file_locked(&enc_hash) {
                return Err(Error::DecryptionFailed);
            }
        }

        let ref_image = StegaV1::load_image(original_img_path, true)?;
        let enc_image = StegaV1::load_image(encoded_img_path, true)?;

        // The reference and encoded images must have the same dimensions.
        if enc_image.dimensions() != ref_image.dimensions() {
            return Err(Error::ImageDimensionsMismatch);
        }

        // Generate the composite key from the hash of the original
        //   file and the key.
        let mut composite_key = StegaV1::generate_composite_key(original_img_path, key)?;

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
        let total_ct_cells = data.pop_u32();

        // Now we can calculate how many bytes we need to read.
        let total_cells_needed = (4 /* number of cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (12 * u8) */
            + 12 /* the length of the AES-256 nonce (12 * u8) */
            + total_ct_cells as usize)
            * 2; /* 2 subcells per cell */

        /*
          In total we will never store more than 0xFFFFFFFF bytes of data.
          This is done to keep the total number of cells below the maximum
            possible value for an unsigned 32-bit integer.
        */
        if total_cells_needed > u32::MAX as usize {
            // This error counts as a failed decryption attempt.
            self.update_file_lock(encoded_img_path, &enc_hash);
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to decode the data?
        if total_cells_needed > StegaV1::get_total_cells(&enc_image) {
            // This error counts as a failed decryption attempt.
            self.update_file_lock(encoded_img_path, &enc_hash);
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
        let ct_bytes = data.pop_vec(total_ct_cells as usize);

        // Now we can compute the Argon2 hash.
        let key_bytes_full = hashers::argon2_string(
            &composite_key,
            salt_bytes,
            M_COST,
            P_COST,
            T_COST,
            ARGON_VER,
        )?;

        // Clear the key since it is no longer needed.
        composite_key.clear();

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
        let pt_bytes = match cipher.decrypt(nonce, ct_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                // This error counts as a failed decryption attempt.
                self.update_file_lock(encoded_img_path, &enc_hash);
                return Err(Error::DecryptionFailed);
            }
        };

        // The decryption was successful, we can remove any file access
        //   attempts that might be present.
        // We will never clear the attempts for a file that has the
        //   read-once flag.
        if !self.is_read_once_enabled() {
            self.clear_file_lock(&enc_hash);
        }

        let str: String;
        unsafe {
            // The following code is safe.
            // We are working with internal code and it can't
            //   generate any invalid UTF-8 sequences.
            str = String::from_utf8_unchecked(pt_bytes);
        }

        // We successfully decrypt the data.
        // Was the read-once flag set for this file?
        if !str.is_empty() && self.is_read_once_enabled() {
            /*
              Update the attempts counter and attempt to lock the file.
              We intentionally do this, rather than directly locking the file,
                since we will try to lock the file again next time, should the
                locking attempt fail here.
            */
            self.locker.set_attempts(encoded_img_path, &enc_hash, 4);
        }

        Ok(str)
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
        let mut img = StegaV1::load_image(original_img_path, false)?;

        // Generate the composite key from the hash of the original file and the key.
        let mut composite_key = StegaV1::generate_composite_key(original_img_path, key)?;

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; 12] = misc_utils::secure_random_bytes();
        let key_bytes_full = hashers::argon2_string(
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
        let plaintext = misc_utils::encode_u8_slice_to_base64_str(data);
        let Ok(ct_bytes) = cipher.encrypt(nonce, plaintext.as_bytes()) else {
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
        let total_cells_needed = (4 /* number of cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (12 * u8) */
            + 12 /* the length of the AES-256 nonce (12 * u8) */
            + ct_bytes.len())
            * 2; /* 2 subcells per cell */

        // In total we can never store more than 0xFFFFFFFF bytes of data to
        //   ensure that the values of usize never exceeds the maximum value
        //   of the u32 type.
        if total_cells_needed > u32::MAX as usize {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to encode the data?
        let total_cells = StegaV1::get_total_cells(&img);
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

        // Clear the key since it is no longer needed.
        composite_key.clear();

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
            self.modify_png_file(encoded_img_path)
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
        *self
            .data_cell_map
            .get(data_index)
            .expect("The data index was not found in the cell map")
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
            combined with the plaintext key.

          It intentional that we take ownership of the key as it will be
            cleared from memory when this function exits.
        */

        let file_hash_bytes = hashers::sha3_512_file(original_path)?;

        let mut composite_key = key.into_bytes();
        composite_key.extend_from_slice(&file_hash_bytes);

        Ok(composite_key)
    }

    /// Generate the bKGD chunk data containing the encoded flags.
    ///
    fn generate_bkgd_chunk_data(&self) -> [u8; 6] {
        let mut data: [u8; 6] = misc_utils::secure_random_bytes();

        // The 1st bit will be stored in byte 1.
        misc_utils::set_bit_state(&mut data[0], 0, self.is_file_locker_enabled());

        // The 2nd to 4th bits will be restores in bytes 2 to 4 respectively.
        // Bits 3 and 4 are currently reserved for future use.
        misc_utils::set_bit_state(&mut data[1], 0, self.is_read_once_enabled());
        misc_utils::set_bit_state(&mut data[2], 0, false);
        misc_utils::set_bit_state(&mut data[3], 0, false);

        // 5th and 6th bits will be stored in byte 5.
        // These are currently reserved for future use.
        misc_utils::set_bit_state(&mut data[4], 0, false);
        misc_utils::set_bit_state(&mut data[4], 1, false);

        // 7th and 8th bits will be stored in byte 6.
        // These are currently reserved for future use.
        misc_utils::set_bit_state(&mut data[5], 0, false);
        misc_utils::set_bit_state(&mut data[5], 1, false);

        // Return the data.
        data
    }

    /// Is the file locker enabled for this file?
    ///
    #[inline]
    fn is_file_locker_enabled(&self) -> bool {
        misc_utils::is_bit_set(&self.flags, 0)
    }

    /// Is the file locker system required for this task?
    ///
    #[inline]
    fn is_locker_needed(&self) -> bool {
        self.is_file_locker_enabled() || self.is_read_once_enabled()
    }

    /// Is the read-once file locker enabled for this file?
    ///
    #[inline]
    fn is_read_once_enabled(&self) -> bool {
        misc_utils::is_bit_set(&self.flags, 1)
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
        StegaV1::validate_image(&img)?;

        Ok(img)
    }

    /// Directly modifies a PNG file to add additional encoding data.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    ///
    fn modify_png_file(&self, file_path: &str) -> Result<()> {
        // Generate the bKGD chunk containing our flags.
        let chunk = self.generate_bkgd_chunk_data();

        // Write the chunk data to the file. If the chunk
        //   is already present then the data will be overwritten.
        png_utils::insert_or_replace_bkgd_chunk(file_path, &chunk)
    }

    /// Process the bKGD chunk of a PNG file, and apply any flags that may be present.
    ///
    /// * `path` - The path to the PNG file.
    ///
    pub fn process_bkgd_chunk(&mut self, path: &str) -> bool {
        let Some(chunk) = png_utils::read_chunk_raw(path, PngChunkType::Bkgd) else {
            // This is an error as we should always have a bKGD chunk.
            return false;
        };

        // We have a bKGD chunk to process!
        let Some(data) = png_utils::get_chunk_data(&chunk) else {
            // This is an error as we should always have a bKGD chunk.
            return false;
        };

        if data.len() < 6 {
            // This is an error as there should always be 6 bytes.
            return false;
        }

        // The 1st bit are be stored in byte 1.
        // Bit 1 stores the flag indicating whether the file locker should be
        //   used with this file.
        //
        // The 2nd to 4th bits are be stored in bytes 2 to 4 respectively.
        // Bit 2 stores the read-once flag.
        // Bits 3 and 4 are reserved fo future use.
        //
        // 5th and 6th bits are be stored in byte 5.
        // These are currently reserved for future use.
        //
        // 7th and 8th bits are be stored in byte 6.
        // These are currently reserved for future use.

        unsafe {
            self.flags = (misc_utils::is_bit_set(&data[0], 0) as u8) & BIT_MASKS.get_unchecked(0)
                | ((misc_utils::is_bit_set(&data[1], 0) as u8) << 1) & BIT_MASKS.get_unchecked(1)
                | ((misc_utils::is_bit_set(&data[2], 0) as u8) << 2) & BIT_MASKS.get_unchecked(2)
                | ((misc_utils::is_bit_set(&data[3], 0) as u8) << 3) & BIT_MASKS.get_unchecked(3)
                | ((misc_utils::is_bit_set(&data[4], 0) as u8) << 4) & BIT_MASKS.get_unchecked(4)
                | ((misc_utils::is_bit_set(&data[4], 1) as u8) << 5) & BIT_MASKS.get_unchecked(5)
                | ((misc_utils::is_bit_set(&data[5], 0) as u8) << 6) & BIT_MASKS.get_unchecked(6)
                | ((misc_utils::is_bit_set(&data[5], 1) as u8) << 7) & BIT_MASKS.get_unchecked(7);
        }

        true
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

        // This block is safe because we verify that the loaded image has
        //   a total number of channels that is divisible by 8.

        unsafe {
            (*rb.get_unchecked(0) != *eb.get_unchecked(0)) as u8
                | ((*rb.get_unchecked(1) != *eb.get_unchecked(1)) as u8) << 1
                | ((*rb.get_unchecked(2) != *eb.get_unchecked(2)) as u8) << 2
                | ((*rb.get_unchecked(3) != *eb.get_unchecked(3)) as u8) << 3
                | ((*rb.get_unchecked(4) != *eb.get_unchecked(4)) as u8) << 4
                | ((*rb.get_unchecked(5) != *eb.get_unchecked(5)) as u8) << 5
                | ((*rb.get_unchecked(6) != *eb.get_unchecked(6)) as u8) << 6
                | ((*rb.get_unchecked(7) != *eb.get_unchecked(7)) as u8) << 7
        }
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

    /// Set the state a feature flag.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the flag.
    /// * `state` - The intended state of the flag.
    ///
    #[inline]
    fn set_feature_flag_state(&mut self, index: usize, state: bool) {
        misc_utils::set_bit_state(&mut self.flags, index, state);
    }

    /// Update the attempts field for a given file. Only used when use_file_locker is enabled.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `hash` - The hash of the image file.
    ///
    fn update_file_lock(&mut self, path: &str, hash: &Vec<u8>) {
        if !self.is_locker_needed() {
            return;
        }

        // This error counts as a failed decryption attempt.
        self.locker.increment_attempts(path, hash);
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
        // Get the image bytes relevant to this cell.
        let bytes = img.get_subcells_from_index_mut(cell_start, 2);

        for (i, b) in bytes
            .iter_mut()
            .enumerate()
            .filter(|(i, _)| misc_utils::is_bit_set(data, *i))
        {
            // If the value is 0 then the new value will always be 1.
            // If the value is 255 then the new value will always be 254.
            // Otherwise the value will be assigned to be ±1.
            *b = match *b {
                0 => 1,
                1..=254 => {
                    if i % 2 == 0 {
                        *b + 1
                    } else {
                        *b - 1
                    }
                }
                255 => 254,
            };
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
        // If the data is zero then we can fast-path here as we will not
        //   have any actions to undertake.
        if *data == 0 {
            return;
        }

        // We need to look up the cell to which this byte of data
        //   will be encoded within the image.
        // Each cell is 2 subcells (16 channels) in length.
        let start_index = self.get_data_cell_index(&data_index) * 2;

        // Finally we can write a byte of data to the cell.
        self.write_u8(img, data, start_index);
    }
}

impl Codec for StegaV1 {
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
        let b64_str = self.decode_internal(original_img_path, key, encoded_img_path)?;

        // Decode the base64 string into the raw bytes.
        let bytes = misc_utils::decode_base64_str_to_vec(&b64_str)?;

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
        let b64_str = self.decode_internal(original_img_path, key, encoded_img_path)?;

        // Decode the base64 string into the raw bytes.
        let bytes = misc_utils::decode_base64_str_to_vec(&b64_str)?;

        // Write the raw bytes directly to the output file.
        if self.output_files {
            file_utils::write_u8_slice_to_file(output_file_path, &bytes)
        } else {
            Ok(())
        }
    }

    fn set_application_name(&mut self, name: String) {
        self.application_name = name;
    }

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
                self.set_feature_flag_state(0, state);
            }
            Config::ReadOnce => {
                self.set_feature_flag_state(1, state);
            }
        }
    }
}

impl Default for StegaV1 {
    fn default() -> Self {
        Self::new("")
    }
}

impl Drop for StegaV1 {
    fn drop(&mut self) {}
}

/// This structure will hold the decoded data.
///
/// `Note:` this structure handles little Endian conversions internally.
///
struct DataDecoder {
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
struct DataEncoder {
    bytes: Vec<u8>,
    rng: Xoshiro512PlusPlus,
}

impl DataEncoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            //rng: Xoshiro512PlusPlus::from_os_rng(),
            rng: Xoshiro512PlusPlus::from_entropy(),
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

        let vec: Vec<u8> = (0..remainder).map(|_| self.rng.gen()).collect();
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
        let xor = self.rng.gen::<u8>().to_le();
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
mod tests_encode_decode {
    use hashbrown::HashMap;

    use crate::{
        codecs::codec::{Codec, Config},
        hashers,
        utilities::{
            file_utils,
            png_utils::{self, PngChunkType},
            test_utils::*,
        },
    };

    use super::StegaV1;

    // The generic key used for encoding text.
    const KEY: &str = "ElPsyKongroo";
    // The generic text used to text encoding and decoding.
    const TEXT: &str = "3.1415926535";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["encoding_decoding"];

    /// Create a StegaV1 instance.
    ///
    /// `Note:` we will attempt to clear the locker file upon exit by default.
    ///
    fn create_instance() -> StegaV1 {
        use crate::{locker::Locker, logger::Logger};

        let app_name = "PsiStega3-Tests";

        // Create a custom locker instance per test.
        let locker_pf = TestUtils::generate_ascii_string(16);
        let mut locker =
            Locker::new(app_name, &locker_pf).expect("could not initialize the file locker");
        locker.clear_on_exit = true;

        // Return a new StegaV1 instance.
        StegaV1 {
            application_name: app_name.to_string(),
            data_cell_map: HashMap::new(),
            noise_layer: false, // We do not need this here.
            output_files: true,
            flags: 0,
            locker,
            logger: Logger::new(false),
        }
    }

    #[test]
    fn test_composite_string_generation() {
        let tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("text-file.txt");
        let key = StegaV1::generate_composite_key(&input_path, KEY.to_string())
            .expect("failed to generate a composite key");
        let expected_key = vec![
            0x45, 0x6C, 0x50, 0x73, 0x79, 0x4B, 0x6F, 0x6E, 0x67, 0x72, 0x6F, 0x6F, 0x47, 0x86,
            0x72, 0x42, 0xB4, 0xA8, 0x8A, 0x61, 0x70, 0x53, 0xE7, 0xA0, 0xB2, 0xB8, 0x77, 0x1A,
            0x2D, 0x7B, 0x4F, 0x2D, 0x65, 0x97, 0xAE, 0xDE, 0x06, 0x6C, 0x45, 0xF2, 0x42, 0x4C,
            0xF9, 0x33, 0xEA, 0x87, 0xCE, 0x48, 0x93, 0x99, 0x42, 0xAD, 0xA4, 0x1A, 0xB0, 0xEA,
            0xDB, 0x7B, 0x0B, 0x46, 0x63, 0xBA, 0x51, 0x68, 0x7E, 0x03, 0x6C, 0x14, 0xAE, 0x54,
            0xE1, 0xCA, 0xC0, 0x36, 0x0A, 0x05,
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

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode(&input_path, KEY.to_string(), TEXT, &output_img_path);

        assert!(
            file_utils::path_exists(&output_img_path),
            "file not written to disk."
        );

        // Did we successfully encode the string?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("text-file.txt");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode_file(
            &input_path,
            KEY.to_string(),
            &input_file_path,
            &output_img_path,
        );

        assert!(
            file_utils::path_exists(&output_img_path),
            "file not written to disk"
        );

        // Did we successfully encode the file?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_file_binary() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let input_file_path = tu.get_in_file("binary-file.bin");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        let r = stega.encode_file(
            &input_path,
            KEY.to_string(),
            &input_file_path,
            &output_img_path,
        );

        assert!(
            file_utils::path_exists(&output_img_path),
            "file not written to disk."
        );

        // Did we successfully encode the file?
        assert_eq!(r, Ok(()), "failed to encode data into image file");
    }

    #[test]
    fn test_encode_decode_locker_enabled() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        // We want to enable the file locker system here.
        stega.set_config_state(Config::Locker, true);

        stega
            .encode(&input_path, KEY.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        // Disable the file locker system again.
        stega.set_config_state(Config::Locker, false);

        // Attempt to decode the string.
        stega
            .decode(&input_path, KEY.to_string(), &output_img_path)
            .expect("failed to decode the data");

        // Was the file locker enabled upon decoding?
        assert!(
            stega.is_file_locker_enabled(),
            "file locker was not enabled after decoding the file"
        );
    }

    #[test]
    fn test_encode_decode_read_once_enabled() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        // We want to enable the read-once file locker system here.
        stega.set_config_state(Config::ReadOnce, true);

        stega
            .encode(&input_path, KEY.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        // Disable the read-once file locker system again.
        stega.set_config_state(Config::ReadOnce, false);

        // Attempt to decode the string.
        stega
            .decode(&input_path, KEY.to_string(), &output_img_path)
            .expect("failed to decode the data");

        // Was the read-once file locker enabled upon decoding?
        assert!(
            stega.is_read_once_enabled(),
            "read-once was not enabled after decoding the file"
        );

        // Was the read-once file locked after decoding the data?
        assert!(
            stega.is_read_once_enabled(),
            "read-once was not enabled after decoding the file"
        );
    }

    #[test]
    fn test_read_once_roundtrip_successful() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        // We want to enable the read-once file locker system here.
        stega.set_config_state(Config::ReadOnce, true);

        stega
            .encode(&input_path, KEY.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        // Hash the original file, this should change upon successful decryption.
        let hash_original = hashers::sha3_512_file(&output_img_path);

        // Attempt to decode the string.
        stega
            .decode(&input_path, KEY.to_string(), &output_img_path)
            .expect("failed to decode the data");

        // Hash the file again.
        let hash_new = hashers::sha3_512_file(&output_img_path);

        // Was the read-once file locked after successfully decoding the data?
        assert_ne!(
            hash_original, hash_new,
            "the read-once file was not successfully locked after successful decryption attempt"
        );
    }

    #[test]
    fn test_read_once_roundtrip_unsuccessful() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();

        // We want to enable the read-once file locker system here.
        stega.set_config_state(Config::ReadOnce, true);

        stega
            .encode(&input_path, "banana".to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        // Hash the original file, this should not change upon unsuccessful decryption.
        let hash_original =
            hashers::sha3_512_file(&output_img_path).expect("failed to create file hash");

        // Attempt to decode the string. We do not care about the return result here.
        _ = stega.decode(&input_path, KEY.to_string(), &output_img_path);

        // Hash the file again.
        let hash_new =
            hashers::sha3_512_file(&output_img_path).expect("failed to create file hash");

        // Was the read-once file locked after failing to decoding the data?
        assert_eq!(
            hash_original, hash_new,
            "the read-once file was locked after unsuccessful decryption attempt"
        );

        // No locker entry should exist for the file in this instance.
        let locker_entry = stega.locker.get_entry_by_hash(&hash_original);
        assert!(
            locker_entry.is_none(),
            "found a locker entry when none was expected"
        );
    }

    #[test]
    fn test_read_once_roundtrip_with_locker() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);
        let correct_key = "banana";

        // Attempt to encode the file.
        let mut stega = create_instance();

        // We want to enable the read-once file locker and normal file locker system here.
        stega.set_config_state(Config::Locker, true);
        stega.set_config_state(Config::ReadOnce, true);

        stega
            .encode(&input_path, correct_key.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        // Hash the original file.
        let hash_original =
            hashers::sha3_512_file(&output_img_path).expect("failed to create file hash");

        // Attempt to decode the string. We do not care about the return result here.
        _ = stega.decode(&input_path, KEY.to_string(), &output_img_path);

        // A locker entry should exist for the file here.
        let locker_entry = stega.locker.get_entry_by_hash(&hash_original);
        assert!(
            locker_entry.is_some(),
            "no locker entry was found when one was expected"
        );

        // Hash the file again.
        let hash_new =
            hashers::sha3_512_file(&output_img_path).expect("failed to create file hash");

        // Was the file locked?
        // It should not be locked here as a single unsuccessful attempt was made.
        assert_eq!(
            hash_original, hash_new,
            "the read-once file was locked after unsuccessful decryption attempt"
        );

        // Attempt to decode the string. We do not care about the return result here.
        _ = stega
            .decode(&input_path, correct_key.to_string(), &output_img_path)
            .expect("failed to decrypt the data");

        // Hash the file again.
        let hash_final =
            hashers::sha3_512_file(&output_img_path).expect("failed to create file hash");

        // Was the file locked?
        // It should have been locked as it was successfully decoded.
        assert_ne!(
            hash_original, hash_final,
            "the read-once file was not locked after a successful decryption attempt"
        );
    }

    #[test]
    fn test_encode_bkgd_chunk() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        stega
            .encode(&input_path, KEY.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        assert!(
            png_utils::find_chunk_start(&output_img_path, PngChunkType::Bkgd).is_some(),
            "bKGD chunk was not written to the PNG file"
        );
    }

    #[test]
    fn test_decode_string() {
        let tu = TestUtils::new(&BASE);

        let ref_img_path = tu.get_in_file("reference-valid.png");
        let enc_img_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        let mut stega = create_instance();

        let r = stega
            .decode(&ref_img_path, KEY.to_string(), &enc_img_path)
            .expect("failed to decode string");

        // Did we successfully decode the string?
        assert_eq!(r, TEXT, "decrypted information does not match input");
    }

    #[test]
    fn test_decode_string_invalid_key() {
        let tu = TestUtils::new(&BASE);

        let ref_img_path = tu.get_in_file("reference-valid.png");
        let enc_img_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string.
        let mut stega = create_instance();

        let r = stega.decode(&ref_img_path, "A".to_string(), &enc_img_path);

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
    fn test_decode_file() {
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
    fn test_decode_file_binary() {
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

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        let invalid_utf8 = unsafe { String::from_utf8_unchecked(vec![65, 159, 146, 150, 65]) };

        // Attempt to encode the file.
        let mut stega = create_instance();

        let r = stega.encode(
            &input_path,
            KEY.to_string(),
            &invalid_utf8,
            &output_img_path,
        );

        assert!(
            file_utils::path_exists(&output_img_path),
            "file not written to disk"
        );

        // Did we successfully encode the string?
        assert_eq!(r, Ok(()), "failed to encode data into image file");

        // Now we will attempt to decode the string.
        let str = stega
            .decode(&input_path, KEY.to_string(), &output_img_path)
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

    use super::StegaV1;

    /// The sub directory to the test files.
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
            let result = match StegaV1::load_image(&path, true) {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            };

            assert_eq!(result, test.expected_result, "{}", test.fail_message());
        }
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
