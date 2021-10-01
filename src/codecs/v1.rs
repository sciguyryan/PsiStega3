use crate::codecs::codec::{Codec, DATA_HEADER};
use crate::error::{Error, Result};
use crate::hashers::*;
use crate::image_wrapper::ImageWrapper;
use crate::utils;

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::convert::TryFrom;

// TODO - decide if we should use AES-GCM for AES-GCM-SIV. Slightly decreased performance, increased resistance to certain types of attack.
// TODO - this might be something that is used in a v2 algorithm if not implemented here.

/// The time cost for use with the Argon2 hashing algorithm.
const T_COST: u32 = 6;
/// The parallel cost for use with the Argon2 hashing algorithm.
const P_COST: u32 = 3;
/// The memory cost for use with the Argon2 hashing algorithm.
const M_COST: u32 = 4096;
/// The version of the Argon2 hashing algorithm to use.
const ARGON_VER: argon2::Version = argon2::Version::V0x13;
/// The maximum number of cells that an image may contain.
const MAX_CELLS: u64 = 50_000_000;
/// The minimum number of cells that an image may contain.
const MIN_CELLS: u64 = 312;
/// The version of this codec.
const VERSION: u8 = 0;

#[derive(Debug)]
enum ImageType {
    Encoded,
    Reference,
}

#[derive(Debug)]
pub struct StegaV1 {
    /// The data index to cell ID map.
    data_cell_map: HashMap<usize, usize>,
    /// The read-only reference image.
    reference_img: ImageWrapper,
    /// The writable output image.
    encoded_img: ImageWrapper,
    /// A RNG that will be used to handle data adjustments.
    data_rng: ThreadRng,
}

impl StegaV1 {
    pub fn new() -> Self {
        Self {
            data_cell_map: HashMap::with_capacity(1),
            reference_img: ImageWrapper::new(),
            encoded_img: ImageWrapper::new(),
            data_rng: thread_rng(),
        }
    }

    /// Builds a map of data indices to cell indices.
    ///
    /// # Arguments
    ///
    /// * `key` - The key that should be used to seed the random number generator.
    ///
    fn build_data_to_cell_index_map(&mut self, key: &str) {
        /*
          When seeding our RNG, we can't use the Argon2 hash for the
          positional random number generator as we will need the salt,
          which will not be available when initially reading the data
          back from the file.
        */
        let hash_bytes = Hashers::sha3_256_string(key);
        let mut rng: ChaCha20Rng = StegaV1::u8_vec_to_seed(&hash_bytes);

        let next: u32 = rng.gen();
        log::debug!("RNG test = {}", next);

        // It doesn't matter if we call this on reference or encoded
        // as they will have the same value at this point.
        let total_cells = self.get_total_cells(&ImageType::Reference) as usize;

        // Create and fill our vector with sequential values, one
        // for each cell ID.
        let mut cell_list = Vec::with_capacity(total_cells);
        utils::fill_vector_sequential(&mut cell_list);

        // Randomize the order of the cell IDs.
        cell_list.shuffle(&mut rng);

        // Add the randomized entries to our cell map.
        self.data_cell_map = HashMap::with_capacity(total_cells);
        let mut i = 0;
        while let Some(cell_id) = cell_list.pop() {
            self.data_cell_map.insert(i, cell_id);
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

    /// Gets a reference to the internal encoded or reference image.
    ///
    /// # Arguments
    ///
    /// * `img_type` - The [`ImageType`] of the image.
    ///
    fn get_internal_image(&self, img_type: &ImageType) -> &ImageWrapper {
        // This will be a reference to the underlying struct
        // field that we will be modifying.
        match img_type {
            ImageType::Encoded => &self.encoded_img,
            ImageType::Reference => &self.reference_img,
        }
    }

    /// Gets a mutable reference to the internal encoded or reference image.
    ///
    /// # Arguments
    ///
    /// * `img_type` - The [`ImageType`] of the image.
    ///
    fn get_internal_image_mut(&mut self, img_type: &ImageType) -> &mut ImageWrapper {
        // This will be a reference to the underlying struct
        // field that we will be modifying.
        match img_type {
            ImageType::Encoded => &mut self.encoded_img,
            ImageType::Reference => &mut self.reference_img,
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

    /// Calculate the total number of cells available in the reference image.
    ///
    /// # Arguments
    ///
    /// * `img_type` - The [`ImageType`] of the image.
    ///
    #[inline]
    fn get_total_cells(&self, img_type: &ImageType) -> u64 {
        // 1 byte is 8 bits in length.
        // We  can store 1 bit per channel.
        self.get_internal_image(img_type).get_total_channels() / 8
    }

    /// Sets the encoded or reference images.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    /// * `img_type` - The [`ImageType`] of the image.
    /// * `read_only` - The read-only state of the image.
    ///
    fn load_image(&mut self, file_path: &str, img_type: ImageType, read_only: bool) -> Result<()> {
        // See: https://github.com/image-rs/image
        let wrapper = ImageWrapper::load_from_file(file_path)?;

        // This will be a reference to the underlying struct
        // field that we will be modifying.
        let img = self.get_internal_image_mut(&img_type);

        // Assign the image to the struct field.
        *img = wrapper;
        img.set_read_only(read_only);

        // Validate if the image file can be used.
        self.validate_image(img_type)?;

        Ok(())
    }

    /// Read a byte of encoded data, starting at a specified index.
    ///
    /// # Arguments
    ///
    /// * `cell_start` - The index from which the encoded data should be read.
    ///
    /// Note: this method will read 8 channels worth of data, starting at
    /// the specified index.
    ///
    fn read_byte(&self, cell_start: usize) -> u8 {
        // Extract the bytes representing the pixel channels
        // from the images.
        let ref_bytes = self.reference_img.get_subcells_from_index(cell_start, 2);

        let enc_bytes = self.encoded_img.get_subcells_from_index(cell_start, 2);

        let mut byte = 0u8;
        for i in 0..8 {
            // This block is actually safe because we verify that the loaded
            // image has a total number of channels that is divisible by 8.
            let ref_c: &u8;
            let enc_c: &u8;
            unsafe {
                // Get the value of the channel for the reference and encoded
                // images.
                ref_c = ref_bytes.get_unchecked(i);
                enc_c = enc_bytes.get_unchecked(i);
            }

            // This is the absolute difference between the channels
            // of the two images.
            let diff = (*ref_c as i32 - *enc_c as i32).abs();

            // We do not need to clear the bit if the variance is
            // zero as the bits are zero by default.
            // This allows us to slightly optimise things here.
            if diff == 0 {
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
    /// * `data_index` - The index of the data byte to be read.
    ///
    /// Note: this method will read 8 channels worth of data, starting at
    /// the specified index.
    ///
    fn read_byte_by_data_index(&self, data_index: usize) -> u8 {
        // First we will look up the cell to which this
        // byte of data will be encoded within the image.
        let cell_index = self.get_data_cell_index(&data_index);

        // Now we will look up the start position for the cell.
        let cell_start_index = self.get_start_by_cell_index(cell_index);

        // Finally we can decode and read a byte of data from the cell.
        self.read_byte(cell_start_index)
    }

    /// Read 2 bytes of data: the XOR'ed value and the XOR value.
    ///
    /// # Arguments
    ///
    /// * `data_index` - The index of the data byte to be read.
    ///
    /// # Returns
    ///
    /// * A byte of data, the result of the XOR operation on the two decoded bytes.
    ///
    /// Note: this method will read 16 channels worth of data: 8 for the
    /// XOR-encoded byte an 8 more for the XOR value byte.
    ///
    fn read_byte_with_xor(&self, data_index: usize) -> u8 {
        let b1 = self.read_byte_by_data_index(data_index);
        let b2 = self.read_byte_by_data_index(data_index + 1);

        u8::from_le(b1) ^ u8::from_le(b2)
    }

    /// Create a seedable RNG object with a defined 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The slice of u8 values to be used as the seed.
    ///
    fn u8_vec_to_seed<R: SeedableRng<Seed = [u8; 32]>>(bytes: &[u8]) -> R {
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
    /// * `img_type` - The [`ImageType`] of the image.
    ///
    fn validate_image(&self, img_type: ImageType) -> Result<()> {
        use image::ImageFormat::*;

        // This will be a reference to the underlying struct
        // field that we will be modifying.
        let internal_img = self.get_internal_image(&img_type);

        let fmt = internal_img.get_image_format();
        log::debug!("Image format: {:?}", fmt);

        // We currently only support for the following formats for
        // encoding: PNG, GIF and bitmap images.
        match fmt {
            Png | Gif | Bmp => {}
            _ => {
                return Err(Error::ImageTypeInvalid);
            }
        }

        let (w, h) = internal_img.dimensions();
        log::debug!("Image dimensions: ({},{})", w, h);

        // The total number of channels must be divisible by 8.
        // This will ensure that we can always encode a given byte
        // of data.
        let channels = self.get_internal_image(&img_type).get_total_channels();
        if channels % 8 != 0 {
            return Err(Error::ImageDimensionsInvalid);
        }

        let total_cells = self.get_total_cells(&img_type);
        log::debug!("Total available cells: {}", &total_cells);

        /*
          We need to ensure that the total number of cells within the reference
          image is not too large.
          This is equal to the number of cells in a 10,000 by 10,000 pixel image.
        */
        if total_cells > MAX_CELLS {
            return Err(Error::ImageTooLarge);
        }

        /*
          We need to ensure that the total number of cells within the reference
          image is not too small.
          This is equal to the number of cells in a 30 by 30 pixel image.
        */
        if total_cells < MIN_CELLS {
            return Err(Error::ImageTooSmall);
        }

        Ok(())
    }

    /// Encode the specified value into the pixels within a given cell.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte value to be encoded.
    /// * `cell_start` - The index of the first pixel of the cell into which the data will be encoded.
    ///
    fn write_byte(&mut self, data: &u8, cell_start: usize) {
        /*
          We convert everything into Little Endian to ensure everything operates
          as expected cross-platform. On a LE platform these will end up being
          no-op calls and so will not impact performance at all.
        */
        let data = data.to_le();
        let bytes = self.encoded_img.get_subcells_from_index_mut(cell_start, 2);

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
    /// * `data` - The byte value to be written to the image.
    /// * `data_index` - The index of the data byte to be written.
    ///
    fn write_byte_by_data_index(&mut self, data: &u8, data_index: usize) {
        // First we will look up the cell to which this
        // byte of data will be encoded within the image.
        let cell_index = self.get_data_cell_index(&data_index);

        // Now we will look up the start position for the cell.
        let cell_start_index = self.get_start_by_cell_index(cell_index);

        // Finally we can write a byte of data to the cell.
        self.write_byte(data, cell_start_index);
    }
}

impl Codec for StegaV1 {
    fn encode(
        &mut self,
        original_path: &str,
        key: &str,
        plaintext: &str,
        encoded_path: &str,
    ) -> Result<()> {
        log::debug!("Loading (reference) image file @ {}", &original_path);
        // The reference image, read-only as it must not be modified.
        // The encoded image will contain all of the encoded data.
        // Initially it is a clone of the reference image but will be modified later.
        self.load_image(&original_path, ImageType::Reference, true)?;
        self.load_image(&original_path, ImageType::Encoded, false)?;

        let file_hash_bytes = Hashers::sha3_512_file(original_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes);

        // The key for the encryption is the SHA3-512 hash of the input image file
        // combined with the plaintext key.
        let mut final_key: String = key.to_string();
        final_key.push_str(&file_hash_string);

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; 12] = utils::secure_random_bytes();
        let key_bytes_full =
            Hashers::argon2_string(&final_key, salt_bytes, M_COST, P_COST, T_COST, ARGON_VER)?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];

        let key = Key::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let nonce_bytes: [u8; 12] = utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes = plaintext.as_bytes();
        let ciphertext_bytes = cipher
            .encrypt(nonce, plaintext_bytes.as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        /*
          2 cells for the magic bytes header, 1 cell for the version,
          4 cells for the total number of cipher-text cells,
          the salt, the nonce and the cipher-text itself.

          This value must be doubled as we need 2 cells per byte:
          one for the XOR encoded byte and one for the XOR byte.

          This value must be held within a 64-bit value to prevent integer overflow
          from occurring in the when running this on a 32-bit architecture.

          Note: a cell represents the space in which a byte of data can be encoded.
        */
        let total_ct_cells = ciphertext_bytes.len();
        let total_cells_needed = (DATA_HEADER.len() as u64 /* magic bytes header */
            + 1 /* version */
            + 4 /* the total number of cipher-text cells */
            + salt_bytes.len() as u64 /* the length of the Argon2 salt */
            + nonce_bytes.len() as u64 /* the length of the AES-256 nonce */
            + total_ct_cells as u64)
            * 2; /* 2 pixels per cell */
        log::debug!("Cells needed to encode data: {}", total_cells_needed);

        // In total we can never store more than 0xffffffff bytes of data to ensure that the values
        // of usize never exceeds the maximum value of the u32 type.
        if total_cells_needed > 0xffffffff {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to encode the data?
        let total_cells = self.get_total_cells(&ImageType::Reference);
        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // This will hold all of the data to be encoded.
        let mut data = DataEncodeWrapper::new(total_cells as usize);

        // We can now safely shadow this value as we have
        // constrained them to within a 32-bit value limit.
        let total_cells_needed = total_cells_needed as u32;

        // Push some data.
        data.push_u8_slice_with_xor(&DATA_HEADER);

        let str_bytes = String::from("Hello, world!").into_bytes();
        data.push_u8_slice_with_xor(&str_bytes);

        // We need to fill the other cells with junk data.
        // Luckily we have a helper method to do this for us!
        // TODO: it might not be necessary to fill every unused pixel
        // TODO: with random data. It might be safe to just write the
        // TODO: cells that we are interested in here.
        // TODO: that would dramatically improve performance.
        data.fill_empty_values();

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&final_key);

        // Clear the key since it is no longer needed.
        final_key.clear();

        // Iterate over each byte of data to be encoded.
        for (i, byte) in data.bytes.iter().enumerate() {
            self.write_byte_by_data_index(byte, i);
        }

        // Save the modified image.
        let r = self.encoded_img.save(encoded_path);
        log::debug!("result = {:?}", r);

        Ok(())
    }

    fn decode(&mut self, original_path: &str, key: &str, encoded_path: &str) -> Result<&str> {
        log::debug!("Loading (reference) image file @ {}", &original_path);
        self.load_image(original_path, ImageType::Reference, true)?;

        log::debug!("Loading (encoded) image file @ {}", &encoded_path);
        self.load_image(encoded_path, ImageType::Encoded, true)?;

        // The reference and encoded images must have the same dimensions.
        if self.encoded_img.dimensions() != self.reference_img.dimensions() {
            return Err(Error::ImageDimensionsMismatch);
        }

        let file_hash_bytes = Hashers::sha3_512_file(original_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes);

        // The key for the encryption is the SHA3-512 hash of the input image file
        // combined with the plaintext key.
        let mut final_key: String = key.to_string();
        final_key.push_str(&file_hash_string);

        // Build the data index to positional cell index map.
        self.build_data_to_cell_index_map(&final_key);

        let original_byte_1 = self.read_byte_with_xor(0);
        log::debug!("byte 1: {}", original_byte_1);

        // Remember, index 1 is the XOR byte, so the next byte of data
        // will be read from cells 2 and 3.
        let original_byte_2 = self.read_byte_with_xor(2);
        log::debug!("byte 2: {}", original_byte_2);

        let header = [original_byte_1, original_byte_2];
        if header == DATA_HEADER {
            log::debug!("We found a valid header! 🙂");
        } else {
            log::debug!("We did not find a valid header! 😢");
        }

        //let b = vec![original_byte_1, original_byte_2];
        //let s = String::from_utf8(b).unwrap();
        //println!("s = {}", s);

        let mut bytes: Vec<u8> = Vec::new();
        for (i, v) in (4..30).step_by(2).enumerate() {
            let b = self.read_byte_with_xor(v);
            bytes.push(b);
        }

        log::debug!("Message = {}", String::from_utf8(bytes).unwrap());

        /*
        // Iterate over each byte of data that is encoded.
        for (i, byte) in data.bytes.iter().enumerate() {
            //log::debug!("Searching for data index = {}.", di);
            // Locate the index of the vector that contains the
            // index of this data byte.
            let cell_id = self.get_data_cell_index(&i);
            self.write_byte_by_cell_id(byte, cell_id);
        }*/

        /*let plaintext_bytes = cipher.decrypt(nonce, ciphertext_bytes.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        log::debug!("Plaintext bytes: {:?}", plaintext_bytes);

        // This code will not be kept around, so we can safely use clone here.
        let plaintext_str = match String::from_utf8(plaintext_bytes.clone()) {
            Ok(s) => s,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        log::debug!("Plaintext string: {}", plaintext_str);*/

        // Todo: clear final key after decryption completed.

        Ok("")
    }
}

impl Default for StegaV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// This structure will hold data to be encoded into an image.
///
/// Note: this structure handles little Endian conversions
/// internally.
pub struct DataEncodeWrapper {
    bytes: Vec<u8>,
    rng: ChaCha20Rng,
}

impl DataEncodeWrapper {
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    #[deprecated]
    #[allow(dead_code)]
    pub fn fill_empty_values_old(&mut self) {
        let mut vec: Vec<u8> = (self.bytes.len()..self.bytes.capacity())
            .map(|_| self.rng.gen())
            .collect();

        self.bytes.append(&mut vec);
    }

    /// Fill any unused slots in the byte list with random byte data.
    pub fn fill_empty_values(&mut self) {
        utils::fast_fill_vec_random(&mut self.bytes, &mut self.rng);
    }

    /// Add a byte of data into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    fn push_value(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Push a sequence of XOR-encoded bytes from a slice into the byte list.
    ///
    /// # Arguments
    ///
    /// * `slice` - The slice of bytes to be stored.
    ///
    /// `Note:` byte yielded by the slice will be added `2` bytes to the internal byte list.
    ///
    /// `Note:` the 1st byte will be the XOR-encoded data and the second will be the XOR value byte.
    pub fn push_u8_slice_with_xor(&mut self, slice: &[u8]) {
        for b in slice {
            self.push_value_with_xor(*b);
        }
    }

    /// Push a XOR-encoded byte into the byte list.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte to be stored.
    ///
    /// `Note:` every byte added will add `2` bytes to the internal byte list.
    ///
    /// `Note:` the 1st byte will be the XOR-encoded data and the second will be the XOR value byte.
    pub fn push_value_with_xor(&mut self, value: u8) {
        let xor = self.rng.gen::<u8>().to_le();
        let xor_data = value.to_le() ^ xor;
        self.push_value(xor_data);
        self.push_value(xor);
    }
}
