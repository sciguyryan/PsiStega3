use crate::{
    codecs::codec::Codec,
    error::{Error, Result},
    hashers,
    image_wrapper::ImageWrapper,
    locker::Locker,
    logger::Logger,
    macros::*,
    utilities::*,
};

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::{
    collections::{HashMap, VecDeque},
    convert::{TryFrom, TryInto},
};

use super::codec::Config;

/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const M_COST: u32 = 65536;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VER: argon2::Version = argon2::Version::V0x13;

pub struct StegaV1 {
    /// The application name.
    application_name: String,
    /// The data index to cell ID map.
    data_cell_map: HashMap<usize, usize>,
    /// If the noise layer should be applied to the output image.
    noise_layer: bool,
    /// If the resulting image file should be saved when encoding.
    output_files: bool,
    /// If the faster method of setting the bit variance should be
    /// used.
    ///
    /// This method will not use randomness to determine the pixel value variance
    /// and will instead alternate between adding and subtracting 1.
    fast_variance: bool,
    /// Flags for use when encoding and decoding.
    /// Bit 0 indicates that the file locker is to be used with this file.
    /// Bits 1 to 7 are reserved for future use.
    flags: u8,
    /// The file locker instance for this codec.
    pub(crate) locker: Locker,
    /// The logger instance for this codec.
    logger: Logger,
}

impl StegaV1 {
    pub fn new(application_name: &str) -> Self {
        let mut application_name = application_name;
        if application_name.is_empty() {
            application_name = "PsiStega3"
        }

        #[cfg(test)]
        let locker =
            Locker::new(application_name, "").expect("could not initialize the file locker");

        #[cfg(not(test))]
        let locker = Locker::new(application_name).expect("could not initialize the file locker");

        Self {
            application_name: application_name.to_string(),
            data_cell_map: HashMap::with_capacity(1),
            noise_layer: true,
            output_files: true,
            fast_variance: false,
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
        let bytes = hashers::sha3_256_bytes(key);
        let mut rng: ChaCha20Rng = StegaV1::u8_slice_to_seed(&bytes);

        // It doesn't matter if we call this on reference or encoded
        // as they will have the same value at this point.
        let total_cells = StegaV1::get_total_cells(img) as usize;

        // Create and fill our vector with sequential values, one
        // for each cell ID.
        let mut cell_list = Vec::with_capacity(total_cells);
        misc_utils::fill_vector_sequential(&mut cell_list);

        // Randomize the order of the cell IDs.
        cell_list.shuffle(&mut rng);

        // Add the randomized entries to our cell map.
        self.data_cell_map = HashMap::with_capacity(total_cells);
        let mut i = 0;
        while let Some(id) = cell_list.pop() {
            self.data_cell_map.insert(i, id);
            i += 1;
        }
    }

    /// Cipher the flag byte, for use when reading or writing the zTXt chunk of a PNG file.
    ///
    /// # Arguments
    ///
    /// * `flags` - The value of the flag u8.
    /// * `last_byte` - The last junk u8 value in the chunk.
    ///
    fn cipher_flag_byte(flags: &mut u8, last: &u8) {
        *flags = !(*flags ^ !last)
    }

    /// Clear the lock on a file. Only used when use_file_locker is enabled.
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn clear_file_lock(&mut self, hash: &[u8]) {
        if !self.is_file_locker_enabled() {
            return;
        }

        // The decryption was successful, we can remove any file locker
        // attempts that might be present.
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
        // Process the zTXt chunk data, if present.
        self.process_ztxt_chunk(encoded_img_path);

        let mut enc_hash: Vec<u8> = vec![];
        if self.is_file_locker_enabled() {
            enc_hash = unwrap_or_return_err!(
                hashers::sha3_256_file(encoded_img_path),
                Error::FileHashingError
            );

            // The first thing we need to do is to check whether the file hash
            // exists within the locker file index.
            // If it does then we need to check whether the file is already locked.
            // if it is then we will not try to decode the file.
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

        // Generate the composite key from the hash of the original file and the key.
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
        // cells that have been encoded.
        let total_ct_cells = data.pop_u32();

        // Now we can calculate how many bytes we need to read.
        let total_cells_needed = (4 /* number of cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (u8) */
            + 12 /* the length of the AES-256 nonce (u8) */
            + total_ct_cells as u64)
            * 2; /* 2 subcells per cell */

        /*
          In total we will never store more than 0xffffffff bytes of data.
          This is done to keep the total number of cells below the maximum
            possible value for an unsigned 32-bit integer.
        */
        if total_cells_needed > u32::MAX as u64 {
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
        let mut data = DataDecoder::new(total_cells_needed as usize);
        for i in 0..total_cells_needed {
            let val = self.read_u8_by_index(&ref_image, &enc_image, i as usize);
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

        let key = Key::from_slice(key_bytes);
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
        // attempts that might be present.
        self.clear_file_lock(&enc_hash);

        let str: String;
        unsafe {
            // The following code is safe.
            // We are working with internal code and it can't
            // generate any invalid UTF-8 sequences.
            str = String::from_utf8_unchecked(pt_bytes);
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

        let key = Key::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let nonce_bytes: [u8; 12] = misc_utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // We will convert the input data byte vector into a base64 string.
        let plaintext = misc_utils::u8_slice_to_base64_string(data);
        let pt_bytes = plaintext.as_bytes();
        let ct_bytes = unwrap_or_return_err!(
            cipher.encrypt(nonce, pt_bytes.as_ref()),
            Error::EncryptionFailed
        );

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
            + 12 /* the length of the Argon2 salt (u8) */
            + 12 /* the length of the AES-256 nonce (u8) */
            + ct_bytes.len() as u64)
            * 2; /* 2 subcells per cell */

        // In total we can never store more than 0xffffffff bytes of data to
        // ensure that the values of usize never exceeds the maximum value
        // of the u32 type.
        if total_cells_needed > 0xffffffff {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to encode the data?
        let total_cells = StegaV1::get_total_cells(&img);
        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // This will hold all of the data to be encoded.
        let mut data = DataEncoder::new(total_cells as usize);

        // Add the total number of cipher-text cells needed.
        data.push_u32(total_ct_cells as u32);

        // Add the Argon2 salt bytes.
        data.push_u8_slice(&salt_bytes);

        // Add the AES nonce bytes.
        data.push_u8_slice(&nonce_bytes);

        // Add the cipher-text bytes.
        data.push_u8_slice(&ct_bytes);

        // Fill all of the unused cells with junk random data.
        // Yes, I know... I'm evil.
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
    /// Note: this method will panic if the data cell is not present in the map.
    /// In practice this should never occur.
    ///
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
    fn get_total_cells(img: &ImageWrapper) -> u64 {
        // 1 byte is 8 bits in length.
        // We  can store 1 bit per channel.
        img.get_total_channels() / 8
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

        let mut composite_key: Vec<u8> = Vec::new();
        composite_key.extend_from_slice(&key.into_bytes());
        composite_key.extend_from_slice(&file_hash_bytes);

        Ok(composite_key)
    }

    /// Generate a zTXt chunk for our PNG. This chunk will hold information
    /// about feature flags set while encoding the file.
    fn generate_ztxt_chunk_data(&self) -> Vec<u8> {
        let junk_bytes = thread_rng().gen_range(122..=176);

        let key = "Comment".to_string();
        let mut data_bytes: Vec<u8> = Vec::with_capacity(junk_bytes * 2);

        // Junk data.
        for _ in 0..=junk_bytes {
            let b = thread_rng().gen_range(1..=255);
            data_bytes.push(b);
        }

        // The flag data byte.
        let mut flags = 0b0000_0000;

        // The 1st bit indicates whether file locking is enabled.
        // The 2nd to 8th bits are reserved for future use.
        misc_utils::set_bit_state(&mut flags, 0, true);

        // Cipher the flag byte in order add some randomness to the value.
        StegaV1::cipher_flag_byte(&mut flags, data_bytes.last().unwrap());

        // Push the flag byte into the vector.
        data_bytes.push(flags);

        // Generate the zTXt chunk from the data.
        file_utils::generate_png_ztxt_chunk(&[key], &[data_bytes])
    }

    /// Is the file locker enabled for this file?
    #[inline]
    fn is_file_locker_enabled(&self) -> bool {
        misc_utils::is_bit_set(&self.flags, 0)
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
        use std::{fs::File, io::Write};

        // Truncate the IEND chunk from the file.
        file_utils::truncate_file(file_path, 12)?;

        let mut f =
            unwrap_or_return_err!(File::options().append(true).open(file_path), Error::File);

        // Generate and write the ztxt chunk to the file.
        let ztxt_chunk = self.generate_ztxt_chunk_data();
        let _wb = f.write(&ztxt_chunk).unwrap();

        // Now we can write the IEND chunk, which indicated the end of the PNG file data.
        // This chunk is always the same, so it can be hardcoded.
        let end = file_utils::IEND.to_vec();
        let _wb = f.write(&end).unwrap();

        Ok(())
    }

    /// Process the zTXt chunk of a PNG file, and apply any flags that may be present.
    ///
    /// * `path` - The path to the PNG file.
    ///
    pub fn process_ztxt_chunk(&mut self, path: &str) {
        let chunk = file_utils::read_png_ztxt_chunk_data(path);
        if chunk.is_none() {
            return;
        }

        // We have a zTXt chunk to process!
        let chunk = chunk.unwrap();
        let len = chunk.len();

        // The final byte in the sequence contains the encoded flags.
        let mut flags = chunk[len - 1];

        // The byte prior to the final byte is used to cipher the flags byte.
        StegaV1::cipher_flag_byte(&mut flags, &chunk[len - 2]);

        self.flags = flags;
    }

    /// Read a byte of encoded data, starting at a specified index.
    ///
    /// # Arguments
    ///
    /// * `ref_img` - A reference to the [`ImageWrapper`] that holds the reference image.
    /// * `enc_img` - A reference to the [`ImageWrapper`] that holds the encoded image.
    /// * `cell_start` - The index from which the encoded data should be read.
    ///
    /// Note: this method will read 8 channels worth of data, starting at
    /// the specified index.
    ///
    fn read_u8(&self, ref_img: &ImageWrapper, enc_img: &ImageWrapper, cell_start: usize) -> u8 {
        // Extract the bytes representing the pixel channels
        // from the images.
        let rb = ref_img.get_subcells_from_index(cell_start, 2);
        let eb = enc_img.get_subcells_from_index(cell_start, 2);

        let mut byte = 0u8;
        for i in 0..8 {
            // This block is actually safe because we verify that the loaded
            // image has a total number of channels that is divisible by 8.
            unsafe {
                // If there the two channels are identical then
                // we do not need to set this bit of the output byte.
                if *rb.get_unchecked(i) == *eb.get_unchecked(i) {
                    continue;
                }
            }

            misc_utils::set_bit_state(&mut byte, i, true);
        }

        byte
    }

    /// Read a byte of encoded data for a specified data index.
    ///
    /// # Arguments
    ///
    /// * `ref_img` - A reference to the [`ImageWrapper`] that holds the reference image.
    /// * `enc_img` - A reference to the [`ImageWrapper`] that holds the encoded image.
    /// * `data_index` - The index of the data byte to be read.
    ///
    /// Note: this method will read 8 channels worth of data, starting at
    /// the specified index.
    ///
    #[inline]
    fn read_u8_by_index(
        &self,
        ref_img: &ImageWrapper,
        enc_img: &ImageWrapper,
        data_index: usize,
    ) -> u8 {
        // We need to look up the cell to which this byte of data
        //will be encoded within the image.
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
        misc_utils::set_bit_state(&mut self.flags, index, state)
    }

    /// Create a seedable RNG object with a defined 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice of u8 values to be used as the seed.
    ///
    fn u8_slice_to_seed<R: SeedableRng<Seed = [u8; 32]>>(bytes: &[u8]) -> R {
        assert!(
            bytes.len() == 32,
            "Byte vector is not 32 bytes (256-bits) in length."
        );
        let arr = <[u8; 32]>::try_from(bytes).unwrap();

        R::from_seed(arr)
    }

    /// Update the attempts field for a given file. Only used when use_file_locker is enabled.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `hash` - The hash of the image file.
    ///
    fn update_file_lock(&mut self, path: &str, hash: &[u8]) {
        if !self.is_file_locker_enabled() {
            return;
        }

        // This error counts as a failed decryption attempt.
        self.locker.update_file_lock(path, hash);
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    fn validate_image(img: &ImageWrapper) -> Result<()> {
        // We currently only support PNG files.
        if img.get_image_format() != image::ImageFormat::Png {
            return Err(Error::ImageTypeInvalid);
        }

        // The total number of channels must be divisible by 8.
        // This will ensure that we can always encode a given byte
        // of data.
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
    fn write_u8(&mut self, img: &mut ImageWrapper, data: &u8, cell_start: usize) {
        // If the data is zero then we can fast-path here as we will not
        // have any bit set to work with.
        if *data == 0 {
            return;
        }

        // Get the image bytes relevant to this cell.
        let bytes = img.get_subcells_from_index_mut(cell_start, 2);
        for (i, b) in bytes.iter_mut().enumerate() {
            if !misc_utils::is_bit_set(data, i) {
                continue;
            }

            // If the value is 0 then the new value will always be 1.
            // If the value is 255 then the new value will always be 254.
            // Otherwise the value will be assigned to be ±1.
            *b = match *b {
                0 => 1,
                1..=254 => {
                    // We do not need to calculate this if the value is either
                    // 0 or 255. This will slightly improve performance.
                    let add = if self.fast_variance {
                        // We will tend towards the median value
                        // when using the fast variance method.
                        *b <= 128
                    } else {
                        thread_rng().gen_bool(0.5)
                    };

                    if add {
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
        // We need to look up the cell to which this byte of data
        //will be encoded within the image.
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
        let bytes = file_utils::read_file_to_u8_vector(input_file_path)?;

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
        let bytes = misc_utils::base64_string_to_vec(&b64_str)?;

        // Convert the raw bytes back into a string. This is done lossy
        // to ensure that any invalid sequences are handled.
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
        let bytes = misc_utils::base64_string_to_vec(&b64_str)?;

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
            Config::FastVariance => {
                self.fast_variance = state;
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
/// Note: this structure handles little Endian conversions
/// internally.
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
    pub fn decode(&mut self) {
        let len = self.xor_bytes.len() / 2;
        for _ in 0..len {
            let xor_value = self.xor_bytes.pop_front().unwrap();
            let xor = self.xor_bytes.pop_front();

            /*
              If the number of cells is not divisible by 2 then
                the final cell will not have a corresponding XOR cell.
              In that case the final cell value will be the XOR value.
              This is fine as it will contain no useful data in any event.
            */
            if let Some(x) = xor {
                self.bytes.push_back(xor_value ^ x);
            } else {
                self.bytes.push_back(xor_value);
            }
        }

        self.xor_bytes.shrink_to_fit();
    }

    /// Pop a XOR-decoded byte from the front of the byte list.
    pub fn pop_u8(&mut self) -> u8 {
        assert!(!self.bytes.is_empty(), "insufficient values available");

        // We do not need to worry about decoding these values from little
        // Endian because that will have been done when loading the values.
        self.bytes.pop_front().unwrap()
    }

    /// Pop a XOR-decoded u32 from the front of the byte list.
    ///
    /// `Note:` This method will pop `4` bytes from the internal vector.
    ///
    /// `Note:` this method will automatically convert the returned value
    /// from little Endian to the correct bit-format.
    ///
    pub fn pop_u32(&mut self) -> u32 {
        assert!(self.bytes.len() >= 4, "insufficient values available");

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
        assert!(self.bytes.len() >= count, "insufficient values available");

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
    /// `Note:` this method will automatically convert the returned value
    /// from little Endian to the appropriate bit-format.
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
    /// `Note:` this method will automatically convert the returned value
    /// from little Endian to the appropriate bit-format.
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
struct DataEncoder {
    bytes: Vec<u8>,
    rng: ChaCha20Rng,
}

impl DataEncoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    /// Fill any unused slots in the byte list with random byte data.
    pub fn fill_empty_bytes(&mut self) {
        misc_utils::fast_fill_vec_random(&mut self.bytes, &mut self.rng);
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` This method cannot be called outside of the [`DataEncoder`]
    /// class to avoid confusion as it does not XOR encode the byte.
    ///
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
    pub fn push_u8(&mut self, value: u8) {
        let xor = self.rng.gen::<u8>().to_le();
        let xor_data = value.to_le() ^ xor;
        self.push_u8_direct(xor_data);
        self.push_u8_direct(xor);
    }

    /// Add a u32 value of data into the byte list (4 bytes). Each byte will be XOR-encoded.
    ///
    /// # Arguments
    ///
    /// * `value` - The u32 to be stored.
    ///
    pub fn push_u32(&mut self, value: u32) {
        let bytes = value.to_le_bytes();
        self.push_u8_slice(&bytes);
    }
}

#[cfg(test)]
mod tests_encode_decode {
    use crate::{
        codecs::codec::{Codec, Config},
        hashers,
        utilities::{file_utils, test_utils::*},
    };

    use super::StegaV1;

    // The generic key used for encoding text.
    const KEY: &str = "ElPsyKongroo";
    // The generic text used to text encoding and decoding.
    const TEXT: &str = "3.1415926535";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["encoding_decoding"];

    /// Create a StegaV1 instance.
    fn create_instance() -> StegaV1 {
        let mut stega = StegaV1::new("PsiStega3-Tests");

        // These options are not needed for the tests, and should help
        // improve the performance when running them.
        stega.set_config_state(Config::FastVariance, true);
        stega.set_config_state(Config::NoiseLayer, false);

        stega
    }

    #[test]
    fn test_composite_string_generation() {
        let tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("text-file.txt");
        let key = StegaV1::generate_composite_key(&input_path, KEY.to_string())
            .expect("failed to generate a composite key");
        let expected_key = vec![
            0x45, 0x6c, 0x50, 0x73, 0x79, 0x4b, 0x6f, 0x6e, 0x67, 0x72, 0x6f, 0x6f, 0x47, 0x86,
            0x72, 0x42, 0xb4, 0xa8, 0x8a, 0x61, 0x70, 0x53, 0xe7, 0xa0, 0xb2, 0xb8, 0x77, 0x1a,
            0x2d, 0x7b, 0x4f, 0x2d, 0x65, 0x97, 0xae, 0xde, 0x06, 0x6c, 0x45, 0xf2, 0x42, 0x4c,
            0xf9, 0x33, 0xea, 0x87, 0xce, 0x48, 0x93, 0x99, 0x42, 0xad, 0xa4, 0x1a, 0xb0, 0xea,
            0xdb, 0x7b, 0x0b, 0x46, 0x63, 0xba, 0x51, 0x68, 0x7e, 0x03, 0x6c, 0x14, 0xae, 0x54,
            0xe1, 0xca, 0xc0, 0x36, 0x0a, 0x05,
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
    fn test_encode_ztxt_chunk() {
        let mut tu = TestUtils::new(&BASE);

        let input_path = tu.get_in_file("reference-valid.png");
        let output_img_path = tu.get_out_file("png", true);

        // Attempt to encode the file.
        let mut stega = create_instance();
        stega
            .encode(&input_path, KEY.to_string(), TEXT, &output_img_path)
            .expect("failed to encode the data");

        assert!(
            file_utils::find_png_ztxt_chunk_start(&output_img_path).is_some(),
            "zTXt chunk was not written to the PNG file"
        );
    }

    #[test]
    fn test_decode_string() {
        let tu = TestUtils::new(&BASE);

        let ref_img_path = tu.get_in_file("reference-valid.png");
        let enc_img_path = tu.get_in_file("encoded-text.png");

        // Attempt to decode the string, ensure the locker file is cleared on exit.
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

        // Attempt to decode the string, ensure the locker file is cleared on exit.
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

        // Attempt to decode the string, ensure the locker file is cleared on exit.
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
        let output_file_path = tu.get_out_file("png", true);

        // Attempt to decode the file, ensure the locker file is cleared on exit.
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
        let hash_original = hashers::sha3_512_file(&output_file_path);
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

        // Attempt to decode the file, ensure the locker file is cleared on exit.
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

        // Attempt to decode the file, ensure the locker file is cleared on exit.
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
                Err(Error::ImageOpening),
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
