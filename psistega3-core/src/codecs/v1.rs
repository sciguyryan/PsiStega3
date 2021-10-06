use crate::codecs::codec::Codec;
use crate::error::{Error, Result};
use crate::hashers::*;
use crate::image_wrapper::ImageWrapper;
use crate::utils;

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use image::ImageFormat;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::path::Path;

/// The time cost (iterations) for use with the Argon2 hashing algorithm.
const T_COST: u32 = 8;
/// The parallel cost (threads) for use with the Argon2 hashing algorithm.
const P_COST: u32 = 8;
/// The memory cost (kilobytes) for use with the Argon2 hashing algorithm.
const M_COST: u32 = 65536;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VER: argon2::Version = argon2::Version::V0x13;
/// The version of this codec.
const VERSION: u8 = 1;
/// A list of formats that can be used with the v1 algorithm.
const SUPPORTED_FORMATS: [ImageFormat; 3] = [ImageFormat::Png, ImageFormat::Gif, ImageFormat::Bmp];

#[derive(Debug)]
pub struct StegaV1 {
    /// The data index to cell ID map.
    data_cell_map: HashMap<usize, usize>,
    /// The read-only reference image.
    /// A RNG that will be used to handle data adjustments.
    data_rng: ThreadRng,
    /// If the noise layer should be applied to the output image.
    noise_layer: bool,
}

impl StegaV1 {
    pub fn new(noise_layer: bool) -> Self {
        Self {
            data_cell_map: HashMap::with_capacity(1),
            data_rng: thread_rng(),
            noise_layer,
        }
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
        let ref_image = StegaV1::load_image(original_img_path, true)?;
        let enc_image = StegaV1::load_image(encoded_img_path, true)?;

        // The reference and encoded images must have the same dimensions.
        if enc_image.dimensions() != ref_image.dimensions() {
            return Err(Error::ImageDimensionsMismatch);
        }

        let file_hash_bytes = Hashers::sha3_512_file(original_img_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes);

        // The key for the encryption is the SHA3-512 hash of the input image file
        // combined with the plaintext key.
        // It intentional that we take ownership of the key as it will be
        // cleared from memory when this function exits.
        let mut composite_key = key;
        composite_key.push_str(&file_hash_string);

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&enc_image, &composite_key);

        // This will hold all of the decoded data.
        let total_cells = StegaV1::get_total_cells(&enc_image) as usize;
        let mut data = DataDecoder::new(total_cells);

        // Read every byte of data from the images.
        (0..total_cells).for_each(|i| {
            let val = self.read_u8_by_index(&ref_image, &enc_image, i);
            data.push_u8(val);
        });

        // Decode the XOR-encoded values back into the original values.
        data.decode();

        // The first 2 bytes should be the version indicator.
        if data.pop_u8() == VERSION {
        } else {
            return Err(Error::VersionInvalid);
        }

        // The next set of bytes should be the total number of cipher-text bytes
        // cells that have been encoded.
        let total_ct_cells = data.pop_u32();

        let total_cells_needed = (1 /* version (u8) */
            + 4 /* the total number of stored cipher-text cells (u32) */
            + 12 /* the length of the Argon2 salt (u8) */
            + 12 /* the length of the AES-256 nonce (u8) */
            + total_ct_cells as u64)
            * 2; /* 2 subcells per cell */

        // In total we can never store more than 0xffffffff bytes of data to ensure that the values
        // of usize never exceeds the maximum value of the u32 type.
        if total_cells_needed > 0xffffffff {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to decode the data?
        let total_cells = StegaV1::get_total_cells(&enc_image);
        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // Note: we can unwrap these values as we will assert if the
        //   length of the vector is not equal to the length we requested.
        // Next, we get the Argon2 salt bytes.
        let salt_bytes: [u8; 12] = data.pop_vec(12).try_into().unwrap();

        // Next, we get the AES nonce bytes.
        let nonce_bytes: [u8; 12] = data.pop_vec(12).try_into().unwrap();

        // Add the cipher-text bytes.
        let ct_bytes = data.pop_vec(total_ct_cells as usize);

        // Now we can compute the Argon2 hash.
        let key_bytes_full = Hashers::argon2_string(
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
        let nonce = Nonce::from_slice(&nonce_bytes);

        /*
          Attempt to decrypt the cipher-text bytes with
          the extracted information.

          This will fail if the information is invalid, which could occurring
          because of changes to either of the image files, or simply because
          no encrypted information was held inside the images.
        */
        let pt_bytes = match cipher.decrypt(nonce, ct_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(Error::DecryptionFailed),
        };

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

        let file_hash_bytes = Hashers::sha3_512_file(original_img_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes);

        /*
          The key for the encryption is the SHA3-512 hash of the input image file
          combined with the plaintext key.

          It intentional that we take ownership of the key as it will be
          cleared from memory when this function exits.
        */
        let mut composite_key = key;
        composite_key.push_str(&file_hash_string);

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; 12] = utils::secure_random_bytes();
        let key_bytes_full = Hashers::argon2_string(
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
        let nonce_bytes: [u8; 12] = utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // We will convert the input data byte vector into a base64 string.
        let plaintext = utils::u8_slice_to_base64_string(data);
        let pt_bytes = plaintext.as_bytes();
        let ct_bytes = match cipher.encrypt(nonce, pt_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(Error::EncryptionFailed),
        };

        /*
          1 cell for the version,
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
        let total_cells_needed = (1 /* version (u8) */
            + 4 /* the total number of stored cipher-text cells (u32) */
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

        // Add the version indicator.
        data.push_u8(VERSION);

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
        data.bytes.iter().enumerate().for_each(|(i, byte)| {
            self.write_u8_by_data_index(&mut img, byte, i);
        });

        // Save the modified image.
        if let Err(e) = img.save(encoded_img_path) {
            // TODO: Add more granularity here.
            return Err(Error::ImageSaving);
        }

        Ok(())
    }

    /// Builds a map of data indices to cell indices.
    ///
    /// # Arguments
    ///
    /// * `key` - The key that should be used to seed the random number generator.
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    fn build_data_to_cell_index_map(&mut self, img: &ImageWrapper, key: &str) {
        /*
          When we can't use the Argon2 hash for the positional RNG
          as we will need the salt, which will not be available when
          initially reading the data from the file.
        */
        let bytes = Hashers::sha3_256_string(key);
        let mut rng: ChaCha20Rng = StegaV1::u8_slice_to_seed(&bytes);

        // It doesn't matter if we call this on reference or encoded
        // as they will have the same value at this point.
        let total_cells = StegaV1::get_total_cells(img) as usize;

        // Create and fill our vector with sequential values, one
        // for each cell ID.
        let mut cell_list = Vec::with_capacity(total_cells);
        utils::fill_vector_sequential(&mut cell_list);

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
        match self.data_cell_map.get(data_index) {
            Some(index) => *index,
            None => {
                panic!(
                    "The data index {} was not found in the cell map. This should never happen.",
                    data_index
                );
            }
        }
    }

    /// Calculate the start index from which the specified cell originates.
    ///
    /// # Arguments
    ///
    /// * `cell_index` - The cell data index, for which the start index should be calculated.
    ///
    #[inline]
    fn get_start_by_cell_index(&self, cell_index: usize) -> usize {
        // Each cell is 2 subcells (16 channels) in length.
        cell_index * 2
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

    /// Loads an image from file and validates that the image is suitable for steganography.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    /// * `read_only` - The read-only state of the image.
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
        let r_bytes = ref_img.get_subcells_from_index(cell_start, 2);
        let e_bytes = enc_img.get_subcells_from_index(cell_start, 2);

        let mut byte = 0u8;
        for i in 0..8 {
            // This block is actually safe because we verify that the loaded
            // image has a total number of channels that is divisible by 8.
            let ref_b: &u8;
            let enc_b: &u8;
            unsafe {
                // Get the value of the channel for the reference and encoded
                // images.
                ref_b = r_bytes.get_unchecked(i);
                enc_b = e_bytes.get_unchecked(i);
            }

            // We do not need to clear the bit if the variance is
            // zero as the bits are zero by default.
            // This allows us to slightly optimise things here.
            if (*ref_b as i32 - *enc_b as i32).abs() == 0 {
                continue;
            }

            utils::set_bit_state(&mut byte, i, true);
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
        // First we will look up the cell to which this
        // byte of data will be encoded within the image.
        let cell_index = self.get_data_cell_index(&data_index);

        // Now we will look up the start position for the cell.
        let cell_start_index = self.get_start_by_cell_index(cell_index);

        // Finally we can decode and read a byte of data from the cell.
        self.read_u8(ref_img, enc_img, cell_start_index)
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

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `img` - A reference to the [`ImageWrapper`] that holds the image.
    ///
    fn validate_image(img: &ImageWrapper) -> Result<()> {
        let fmt = img.get_image_format();

        // We currently only support for the following formats for
        // encoding: PNG, GIF and bitmap images.
        // TODO: check if any of the other support format types
        // TODO: are suitable for use here.
        // TODO: webp encoding is viable if a dependency on the
        // TODO: webp crate is added.
        if !SUPPORTED_FORMATS.contains(&fmt) {
            return Err(Error::ImageTypeInvalid);
        }

        // This statement is kept around for debugging purposes.
        let (_w, _h) = img.dimensions();

        // The total number of channels must be divisible by 8.
        // This will ensure that we can always encode a given byte
        // of data.
        let channels = img.get_total_channels();
        if channels % 8 != 0 {
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
        /*
          We convert everything into Little Endian to ensure everything operates
          as expected cross-platform. On a LE platform these will end up being
          no-op calls and so will not impact performance at all.
        */
        let data = data.to_le();
        let bytes = img.get_subcells_from_index_mut(cell_start, 2);

        for (i, b) in bytes.iter_mut().enumerate() {
            if !utils::is_bit_set(&data, i) {
                continue;
            }

            // If the value is 0 then the new value will always be 1.
            // If the value is 255 then the new value will always be 254.
            // Otherwise the value will be randomly assigned to be ±1.
            *b = match *b {
                0 => 1,
                1..=254 => {
                    if self.data_rng.gen_bool(0.5) {
                        *b - 1
                    } else {
                        *b + 1
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
        // First we will look up the cell to which this
        // byte of data will be encoded within the image.
        let cell_index = self.get_data_cell_index(&data_index);

        // Now we will look up the start position for the cell.
        let cell_start_index = self.get_start_by_cell_index(cell_index);

        // Finally we can write a byte of data to the cell.
        self.write_u8(img, data, cell_start_index);
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
        encoded_img_path: &str,
        input_file_path: &str,
    ) -> Result<()> {
        if !Path::new(input_file_path).exists() {
            return Err(Error::PathInvalid);
        }

        // Convert the file into a byte vector.
        let bytes = utils::read_file_to_u8_vector(input_file_path)?;

        // Encode the information into the target image.
        self.encode_internal(original_img_path, key, &bytes, encoded_img_path)
    }

    fn decode(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
    ) -> Result<String> {
        // Decode the base64 string.
        let b64_str = self.decode_internal(original_img_path, key, encoded_img_path)?;

        // Decode the base64 string into the raw bytes.
        let bytes = utils::base64_string_to_vector(&b64_str)?;

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
        let bytes = utils::base64_string_to_vector(&b64_str)?;

        // Write the raw bytes directly to the output file.
        utils::write_u8_slice_to_file(output_file_path, &bytes)
    }
}

impl Default for StegaV1 {
    fn default() -> Self {
        Self::new(true)
    }
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

    /// Iterates through each XOR'ed byte and XOR pair, adds the value produced by applying the XOR operation on them to the internal list.
    pub fn decode(&mut self) {
        let len = self.xor_bytes.len() / 2;
        (0..len).for_each(|_| {
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
        });

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
        (0..count).for_each(|_| {
            bytes.push(self.pop_u8());
        });

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
        values.iter().for_each(|v| {
            self.push_u8(*v);
        });
    }
}

/// This structure will hold data to be encoded into an image.
///
/// Note: this structure handles little Endian conversions
/// internally.
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
        utils::fast_fill_vec_random(&mut self.bytes, &mut self.rng);
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` This method cannot be called outside of the [`DataEncoder`]
    /// class to avoid confusion as it does not XOR encode the byte.
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
        slice.iter().for_each(|b| {
            self.push_u8(*b);
        });
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
mod tests_encryption_decryption {
    use crate::error::{Error, Result};

    use super::StegaV1;

    struct TestEntry<'a> {
        pub file: &'a str,
        pub expected_result: Result<()>,
        pub fail_message: &'a str,
    }

    impl<'a> TestEntry<'a> {
        fn new(file: &'a str, expected_result: Result<()>, fail_message: &'a str) -> Self {
            Self {
                file,
                expected_result,
                fail_message,
            }
        }

        fn fail_message(&self) -> String {
            let expected_str = match self.expected_result {
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
                "10x10.jpg",
                Err(Error::ImageTypeInvalid),
                "file type is invalid",
            ),
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
                "10x10-rbga.gif",
                Ok(()),
                "file type is valid, channels % 8 == 0",
            ),
            TestEntry::new(
                "10x10-rbg.bmp",
                Err(Error::ImageDimensionsInvalid),
                "file type is valid, channels % 8 != 0",
            ),
            TestEntry::new(
                "missing-file.png",
                Err(Error::ImageOpening),
                "file is missing and therefore cannot be loaded",
            ),
        ];

        let mut path = std::env::current_dir().unwrap();
        path.push("../tests/assets/loading_and_validation");
        if !path.exists() {
            panic!("unable to find test file path!");
        }

        for test in tests {
            let mut full_path = path.clone();
            full_path.push(test.file);

            let path_str = full_path.as_path().to_str().unwrap();
            let result = match StegaV1::load_image(path_str, true) {
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

        let in_val: u8 = 0xAB;
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

        let in_val: u8 = 0xAB;
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

        let in_val: u8 = 0xAB;
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

        let in_val: u32 = 0xDEADBEEF;
        encoder.push_u32(in_val);
        assert!(encoder.bytes.len() == 8);

        decoder.push_u8_slice(&encoder.bytes);
        decoder.decode();

        assert!(in_val == decoder.pop_u32());
    }
}
