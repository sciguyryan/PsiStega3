use crate::codecs::codec::Codec;
use crate::error::{Error, Result};
use crate::hashers::*;
use crate::image_wrapper::{ImageWrapper, Point};
use crate::utils;

use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce,
};
use image::ColorType;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore};
use std::convert::TryFrom;

// TODO - decide if I want to switch AES-GCM for AES-GCM-SIV. Slightly decreased performance, increased resistance to certain types of attack.
// TODO - this might be something that is used in a v2 algorithm if not implemented here.

/// The time cost for use with the Argon2 hashing algorithm.
const T_COST: u32 = 6;
/// The parallel cost for use with the Argon2 hashing algorithm.
const P_COST: u32 = 3;
/// The memory cost for use with the Argon2 hashing algorithm.
const M_COST: u32 = 4096;
/// The version of the Argon2 hashing algorithm to use.
const VERSION: argon2::Version = argon2::Version::V0x13;
/// The total maximum number of cells that an image may contain.
const MAX_CELLS: u32 = 50_000_000;

#[derive(Debug)]
pub struct StegaV1 {
    /// A list of available cells within the images.
    available_cells: Vec<u32>,
    /// The random number generator used to determine which cells will be used when
    /// storing a given value.
    data_rng: ChaCha20Rng,
    /// The random number generator used to create the XOR values that will be used total number to
    /// XOR the input data.
    position_rng: ChaCha20Rng,
    /// The read-only reference image.
    reference_img: ImageWrapper,
    /// The writable output image.
    encoded_img: ImageWrapper,
}

impl StegaV1 {
    pub fn new() -> Self {
        Self {
            available_cells: Vec::with_capacity(1),
            data_rng: ChaCha20Rng::from_entropy(),
            position_rng: ChaCha20Rng::from_entropy(),
            reference_img: ImageWrapper::new(),
            encoded_img: ImageWrapper::new(),
        }
    }

    /// Calculate the coordinates of the pixel pair that comprise a given cell.
    ///
    /// # Arguments
    ///
    /// * `cell_number` - The cell number.
    ///
    /// Note: This method will return an array of a tuple where the tuple is in the coordinate configuration.
    fn get_cell_pixel_coordinates(&self, cell_number: u32) -> [Point; 2] {
        // Cell 0 contains pixels (0, 1), cell 1 contains pixels (2, 3), etc.
        // The start pixel index can thus be calculated by the equation 2n.
        let start_index = 2 * cell_number;

        [
            self.reference_img.pixel_coordinate(start_index),
            self.reference_img.pixel_coordinate(start_index + 1),
        ]
    }

    /// Calculate the total number of cells available in the reference image.
    ///
    /// Note: This method will return an array of a tuple where the tuple is in the coordinate configuration.
    fn get_total_cells(&self) -> u32 {
        // Each cell is 2x1 pixels in size.
        (self.reference_img.get_total_pixels() / 2) as u32
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `image` - A reference to a [`ImageWrapper`] object.
    ///
    fn validate_image(image: &ImageWrapper) -> Result<()> {
        let fmt = image.get_image_format();
        log::debug!("Image format: {:?}", fmt);

        // We currently only support for the following formats for
        // encoding: PNG, JPEG, GIF and bitmap images.
        match fmt {
            image::ImageFormat::Png
            | image::ImageFormat::Jpeg
            | image::ImageFormat::Gif
            | image::ImageFormat::Bmp => {}
            _ => {
                return Err(Error::ImageTypeInvalid);
            }
        }

        let (w, h) = image.dimensions();
        log::debug!("Image dimensions: ({},{})", w, h);

        let pixels = w * h;
        if pixels % 2 == 0 {
            Ok(())
        } else {
            Err(Error::ImageDimensionsInvalid)
        }
    }

    /// Attempt to load and validate an image file, returning a [`ImageWrapper`] if successful.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    ///
    fn load_image(file_path: &str) -> Result<ImageWrapper> {
        // See: https://github.com/image-rs/image
        let wrapper = ImageWrapper::load_from_file(file_path)?;

        // The image was successfully loaded.
        // Now we need to validate if the file can be used.
        StegaV1::validate_image(&wrapper)?;

        // We currently only operate on files that are RGB(A) with 8-bit colour depth or higher.
        match wrapper.color() {
            ColorType::Rgb8 | ColorType::Rgba8 | ColorType::Rgb16 | ColorType::Rgba16 => {
                Ok(wrapper)
            }
            _ => {
                // We currently do not handle any of the other format types.
                Err(Error::ImageTypeInvalid)
            }
        }
    }

    /// Create a `SeedableRng` object with a specific 32-byte seed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The vector of bytes to be used as the seed.
    ///
    fn u8_vec_to_seed<R: SeedableRng<Seed = [u8; 32]>>(bytes: Vec<u8>) -> R {
        assert!(
            bytes.len() == 32,
            "Byte vector is not 32 bytes (256-bits) in length."
        );
        let arr = <[u8; 32]>::try_from(bytes).unwrap();

        R::from_seed(arr)
    }

    /// Get a random cell ID from the list of available cells.
    fn get_random_available_cell(&mut self) -> u32 {
        let cell_id = self.position_rng.gen_range(0..self.available_cells.len());
        log::debug!("Cell ID: {}", cell_id);

        // We need to ensure that we remove the cell from the available list of cells.
        self.available_cells.remove(cell_id);

        // The cast is safe here as the total number of cells is constrained
        // to fit within an unsigned 32-bit integer.
        cell_id as u32
    }

    /// Write a byte of data into the target image.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte value to be written to the image.
    ///
    /// Note: two cells will be written per byte of raw data.
    /// This is because one cell will hold the XOR-encoded data,
    /// while the other will contain the XOR value itself.
    fn write_byte_pair(&mut self, data: u8) {
        /*
          The process operates as follows:
          1. a random byte will be generated, this byte will be used to
              XOR the input data byte.
          2. a random available cell will be chosen into which the
             XOR encoded data will be written.
          3. a second cell will be chosen into which the XOR value itself
             will be written.
        */
        let xor: u8 = self.data_rng.gen();
        let xor_data = data ^ xor;

        //log::debug!("Original: {}, XOR: {}, XOR'ed data: {}", le_data, le_xor, le_xor_data);

        let cell_pixel_coordinates = self.get_random_available_cell_coords();
        self.write_byte(xor_data, cell_pixel_coordinates);
        //log::debug!("XOR data cell contains pixels: {:?}", cell_pixel_coordinates);

        // Next we will write the XOR value cell.
        let cell_pixel_coordinates = self.get_random_available_cell_coords();
        self.write_byte(xor, cell_pixel_coordinates);
        //log::debug!("XOR value cell contains pixels: {:?}", cell_pixel_coordinates);
    }

    /// Encode the specified value into the pixels within a given cell.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte value to be encoded.
    /// * `coord` - The coordinates of the cell's pixels, into which the data will be encoded.
    ///
    fn write_byte(&mut self, data: u8, coord: [Point; 2]) {
        /*
          We convert everything into Little Endian to ensure everything operates
          as expected cross-platform. On a LE platform these will end up being
          no-op calls and so will not impact performance.
        */
        let data_le = data.to_le();
        log::debug!("Data = 0b{}", utils::u8_to_binary(&data_le).unwrap());

        if utils::is_little_endian() {
            log::debug!("Note: the following bits will be in reverse order if you are working in little Endian (least significant bit first).");
        }

        let mut pixel_1 = self.reference_img.get_pixel_by_coord(coord[0]);
        let mut pixel_2 = self.reference_img.get_pixel_by_coord(coord[1]);

        // This will hold a mutable reference to the current_pixel
        // pixel that we are editing. Naturally we start with pixel 1.
        let mut current_pixel = &mut pixel_1;

        let mut channel: usize = 0;
        for (i, mask) in utils::U8_BIT_MASKS.iter().enumerate() {
            //log::debug!("Pixel {} (bit {}) = {}", (i / 4) + 1, i, utils::is_bit_set2(&data_le, mask));

            if i <= 4 {
                current_pixel = &mut pixel_2;
                channel = 0;
            }

            if utils::is_bit_set2(&data_le, mask) {
                self.nudge_channel_value(&mut current_pixel, channel);
            }

            channel += 1;
        }

        // Write the modified pixels into the encoded data image.
        self.encoded_img.put_pixel_by_coord(coord[0], pixel_1);
        self.encoded_img.put_pixel_by_coord(coord[1], pixel_2);
    }

    /// Nudge the value of a channel by ±1.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The value of the pixel's channels.
    /// * `channel` - The index of the channel to be nudged.
    ///
    fn nudge_channel_value(&mut self, pixel: &mut image::Rgba<u8>, channel: usize) {
        let mut value = pixel[channel];
        //log::debug!("Modified value for channel {} = {}", channel, value);

        if value == 0 {
            // If we have a value of 0 then we can't go any lower without causing an underflow,
            // so we will always add one.
            value = 1;
        } else if value == 255 {
            // If we have a value of 255 then we can't go any higher without causing an overflow,
            // so we will always subtract one.
            value = 254;
        } else {
            // Here we can add or subtract. Which we choose will be determined by
            // a random number generator call.
            // This can never under or overflow due to the checks above.
            if self.data_rng.gen_bool(0.5) {
                value -= 1;
            } else {
                value += 1;
            }
        }

        //log::debug!("Modified value for channel {} = {}", channel, value);
        pixel[channel] = value;
    }

    /// Get the coordinates of the pixels that correspond to a random cell
    /// from the available cell list.
    fn get_random_available_cell_coords(&mut self) -> [Point; 2] {
        let cell = self.get_random_available_cell();
        self.get_cell_pixel_coordinates(cell)
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
        let ref_image = StegaV1::load_image(original_path)?;

        // The reference image, read-only as it must not be modified.
        self.reference_img = ref_image.clone();
        self.reference_img.set_read_only(true);

        // The encoded image will contain all of the encoded data.
        // Initially it is a clone of the reference image but will be modified later.
        self.encoded_img = ref_image;

        let total_cells = self.get_total_cells();
        log::debug!("Total available cells: {}", &total_cells);

        /*
          We need to ensure that the total number of cells within the reference
          image is not too large.
          This avoid any potential overflows and partially to avoids creating
          excessive overheads.
          This is equal to the number of cells in a 10,000 by 10,000 pixel image.
        */
        if total_cells > MAX_CELLS {
            return Err(Error::ImageTooLarge);
        }

        let file_hash_bytes = Hashers::sha3_512_file(original_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes).unwrap(); // This is internal and cannot fail.

        log::debug!("File hash length: {}", file_hash_bytes.len());
        log::debug!("File hash: {}", file_hash_string);

        // The key for the encryption is the SHA3-512 hash of the input image file
        // combined with the plaintext key.
        let mut final_key: String = key.to_string();
        final_key.push_str(&file_hash_string);

        // Generate a random salt for the Argon2 hashing function.
        let salt_bytes: [u8; 12] = utils::secure_random_bytes();
        let key_bytes_full =
            Hashers::argon2_string(&final_key, salt_bytes, M_COST, P_COST, T_COST, VERSION)?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];
        log::debug!("Key hash bytes: {:?}", key_bytes.to_vec());

        let hex_key_hash = utils::u8_array_to_hex(key_bytes).unwrap(); // This is internal and cannot fail.
        log::debug!("Hex key hash: {}", hex_key_hash);

        let key = Key::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let nonce_bytes: [u8; 12] = utils::secure_random_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes = plaintext.as_bytes();
        let ciphertext_bytes = cipher
            .encrypt(nonce, plaintext_bytes.as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        println!("Ciphertext bytes: {:?}", ciphertext_bytes);

        /*let plaintext_bytes = cipher.decrypt(nonce, ciphertext_bytes.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        log::debug!("Plaintext bytes: {:?}", plaintext_bytes);

        // This code will not be kept around, so we can safely use clone here.
        let plaintext_str = match String::from_utf8(plaintext_bytes.clone()) {
            Ok(s) => s,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        log::debug!("Plaintext string: {}", plaintext_str);*/

        /*
          1 cell for the version, 4 cells for the total number of ciphertext cells, the salt, the nonce and the ciphertext.
          This value must be doubled as we need 2 cells per byte:
          one for the XOR encoded byte and one for the XOR byte.
          This value must be held within a 64-bit value to prevent integer overflow from occurring in the
          when running this on a 32-bit architecture.
          This looks ugly, but I'm not sure that there is a better solution for now.
        */
        let total_ct_cells = ciphertext_bytes.len();
        let total_cells_needed =
            (1 + 4 + salt_bytes.len() as u64 + nonce_bytes.len() as u64 + total_ct_cells as u64)
                * 2;
        log::debug!("Total cells needed = {}", total_cells_needed);

        // In total we can never store more than 0xffffffff bytes of data to ensure that the values
        // of usize never exceeds the maximum value of the u32 type.
        if total_cells_needed > 0xffffffff {
            return Err(Error::DataTooLarge);
        }

        // Do we have enough space within the image to encode the data?
        if total_cells_needed > total_cells as u64 {
            return Err(Error::ImageInsufficientSpace);
        }

        // When seeding our RNG, we can't use the Argon2 hash for the positional random number generator
        // as we will need the salt, which will not be available when initially reading the data back from the file.
        let sha256_key_hash_bytes = Hashers::sha3_256_string(&final_key);
        self.position_rng = StegaV1::u8_vec_to_seed(sha256_key_hash_bytes);

        let next: u32 = self.position_rng.gen();
        log::debug!("RNG test = {}", next);

        // This contains the list of every unused cell. Once a cell has been used, it is removed.
        // Initially I had planned to do with with a bitset, but it would require repeatedly checking
        // to see if the cell had been used, which could lower performance in cases where the total
        // number of available cells is close to the total number of cells needed to encode the data.
        // TODO: maybe convert this to a hashmap if it is too large and impacts performance?
        self.available_cells = (0..total_cells).collect();

        let data_byte: u8 = 0xff;
        self.write_byte_pair(data_byte);

        /*
        let version: u8 = 1;
        log::debug!("0b{:08b}", version);

        // We want to make sure that we convert everything into little Endian, to ensure that we can
        // operate cross-platform.
        let le_value = u8::to_le(version);
        log::debug!("0b{:08b}", le_value);

        // The maximum is set above, so this casting is safe.
        let plaintext_cell_bytes = u16::to_le_bytes(plaintext_bytes.len() as u16);

        //let mut i = 0;
        //while i <= 3 {
        //    println!("Is {} bit set? {:?}", &i, is_bit_set(&i, &le_value));
        //    i +=  1;
        //}*/

        // Testing, testing, 1, 2, 3.
        let pixel = self.encoded_img.get_pixel(0, 0);

        println!(
            "rgba = {}, {}, {}, {}",
            pixel[0], pixel[1], pixel[2], pixel[3]
        );

        let new_pixel = image::Rgba([0, 0, 0, 255]);

        self.encoded_img.put_pixel(0, 0, new_pixel);

        // Save the modified image.
        let r = self.encoded_img.save(encoded_path);
        log::debug!("result = {:?}", r);

        Ok(())
    }

    fn decode(&mut self, original_path: &str, key: &str, encoded_path: &str) -> Result<&str> {
        log::debug!("Loading (reference) image file @ {}", &original_path);
        let ref_image = StegaV1::load_image(original_path)?;

        log::debug!("Loading (encoded) image file @ {}", &encoded_path);
        let enc_image = StegaV1::load_image(encoded_path)?;

        // The reference and encoded images must have the same dimensions.
        if ref_image.dimensions() != enc_image.dimensions() {
            return Err(Error::ImageDimensionsMismatch);
        }

        self.reference_img = ref_image;
        self.encoded_img = enc_image;

        /*
          We need to ensure that the total number of cells within the reference
          image is not too large.
          This avoid any potential overflows and partially to avoids creating
          excessive overheads.
          This is equal to the number of cells in a 10,000 by 10,000 pixel image.
        */
        let total_cells = self.get_total_cells();
        if total_cells > MAX_CELLS {
            return Err(Error::ImageTooLarge);
        }

        let file_hash_bytes = Hashers::sha3_512_file(original_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes).unwrap(); // This is internal and cannot fail.

        // The key for the encryption is the SHA3-512 hash of the input image file
        // combined with the plaintext key.
        let mut final_key: String = key.to_string();
        final_key.push_str(&file_hash_string);

        // When seeding our RNG, we can't use the Argon2 hash for the positional random number generator
        // as we will need the salt, which will not be available when initially reading the data back from the file.
        let sha256_key_hash_bytes = Hashers::sha3_256_string(&final_key);
        self.position_rng = StegaV1::u8_vec_to_seed(sha256_key_hash_bytes);

        let next: u32 = self.position_rng.gen();
        log::debug!("RNG test = {}", next);

        Ok("")
    }
}

impl Default for StegaV1 {
    fn default() -> Self {
        Self::new()
    }
}
