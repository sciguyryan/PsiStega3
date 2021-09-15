
use crate::codecs::codec::Codec;
use crate::error::{Error, Result};
use crate::hashers::*;
use crate::image_wrapper::ImageWrapper;
use crate::utils;

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use image::ColorType;
use std::convert::TryFrom;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, OsRng};

/// The time cost for use with the Argon2 hashing algorithm.
const T_COST: u32 = 6;
/// The parallel cost for use with the Argon2 hashing algorithm.
const P_COST: u32 = 3;
/// The memory cost for use with the Argon2 hashing algorithm.
const M_COST: u32 = 4096;
/// The version of the Argon2 hashing algorithm to use.
const VERSION: argon2::Version = argon2::Version::V0x13;

#[derive(Debug)]
pub struct StegaV1 {}

impl StegaV1 {
    pub fn new() -> Self {
        Self {}
     }

    /// Calculate the coordinates of the pixel pair that comprise a given cell.
    ///
    /// # Arguments
    ///
    /// * `img` - a reference to the [`ImageWrapper`] holding the image data.
    /// * `cell_number` - The cell number.
    ///
    /// Note: This method will return an array of a tuple where the tuple is in the coordinate configuration.
    fn get_cell_pixel_coordinates(img: &ImageWrapper, cell_number: usize) -> [(usize, usize); 2] {
        // Cell 0 contains pixels (0, 1), cell 1 contains pixels (2, 3), etc.
        // The start pixel index can thus be calculated by the equation 2n.
        let start_index = 2 * cell_number;

        [
            img.pixel_coordinate(start_index),
            img.pixel_coordinate(start_index + 1)
        ]
    }

    /// Calculate the total number of cells available in the reference image.
    ///
    /// # Arguments
    ///
    /// * `img` - a reference to the [`ImageWrapper`] object.
    ///
    /// Note: This method will return an array of a tuple where the tuple is in the coordinate configuration.
    fn get_total_cells(img: &ImageWrapper) -> u64 {
        // Each cell is 2x1 pixels in size.
        img.get_total_pixels() / 2
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `image` - A reference to a [`ImageWrapper`] object.
    ///
    fn validate_image(image: &ImageWrapper) -> Result<()> {
        let (w, h) =  image.dimensions();

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
        // TODO: determine which image format types should be allowed
        // here. They must support RGBA and they must support
        // writing by the library.
        // See: https://github.com/image-rs/image

        let wrapper = ImageWrapper::load_from_file(file_path)?;

        // The image was successfully loaded.
        // Now we need to validate if the file can be used.
        StegaV1::validate_image(&wrapper)?;

        // We currently only operate on files that are RGB(A) with 8-bit colour depth or higher.
        match wrapper.color() {
            ColorType::Rgb8 |  ColorType::Rgba8 |
            ColorType::Rgb16 | ColorType::Rgba16 => {
                Ok(wrapper)
            },
            _ => {
                // We currently do not handle any of the other format types.
                Err(Error::ImageTypeInvalid)
            }
        }
    }

    fn u8_vec_to_seed<R: SeedableRng<Seed = [u8; 32]>>(bytes: Vec<u8>) -> R {
        assert!(bytes.len() == 32, "Byte vector is not 32 bytes (256-bits) in length.");
        let arr = <[u8; 32]>::try_from(bytes).unwrap();

        R::from_seed(arr)
    }

    fn write_cell_pair(wrapper: &mut ImageWrapper, data_byte: u8, xor_byte: u8) {

    }
}

impl Codec for StegaV1 {
    fn encode(&mut self, original_path: &str, key: &str, plaintext: &str, encoded_path: &str) -> Result<()> {
        log::debug!("Loading (reference) image file @ {}", &original_path);

        // The reference image, read-only as it must not be modified.
        let ref_image = StegaV1::load_image(original_path)?;

        let total_cells = StegaV1::get_total_cells(&ref_image);
        log::debug!("Total available cells: {}", &total_cells);

        // We need to ensure that the total number of cells within the
        // reference image is not too large. This avoid any potential
        // overflows and partially to avoids creating excessive overheads.
        // This is equal to the number of cells in a 10,000 by 10,000 pixel image.
        if total_cells > 50_000_000 {
            return Err(Error::ImageTooLarge);
        }

        // The encoded image will contain all of the encoded data.
        // Initially it is a clone of the reference image but will be modified later.
        let mut enc_image = ref_image.clone();

        let file_hash_bytes = Hashers::sha3_512_file(original_path);
        let file_hash_string = utils::u8_array_to_hex(&file_hash_bytes).unwrap(); // This is internal and cannot fail.

        log::debug!("File hash length: {}" , file_hash_bytes.len());
        log::debug!("File hash: {}", file_hash_string);

        // The key for the encryption is the SHA3-512 hash of the input image file combined with the plaintext key.
        let mut final_key: String = key.to_owned();
        final_key.push_str(&file_hash_string);

        // Generate a random salt for the Argon2 hashing function.
        let mut salt_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt_bytes);

        let key_bytes_full = Hashers::argon2_string(&final_key, salt_bytes, M_COST, P_COST, T_COST, VERSION)?;

        // The AES-256 key is 256-bits (32 bytes) in length.
        let key_bytes = &key_bytes_full[..32];
        log::debug!("Key hash bytes: {:?}", key_bytes.to_vec());

        let hex_key_hash =  utils::u8_array_to_hex(key_bytes).unwrap(); // This is internal and cannot fail.
        log::debug!("Hex key hash: {}", hex_key_hash);

        let key = Key::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate a unique random 96-bit (12 byte) nonce (IV).
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes = plaintext.as_bytes();
        let ciphertext_bytes = cipher.encrypt(nonce, plaintext_bytes.as_ref())
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

        // We can store a maximum of 4,294,967,295 (0xffffffff) bytes of ciphertext.
        let total_ct_cells  = ciphertext_bytes.len() as u64;
        if total_ct_cells > u32::max_value() as u64 {
            return Err(Error::DataTooLarge);
        }

        // 1 cell for the version, 4 cells for the total number of ciphertext cells, the salt, the nonce and the ciphertext.
        // We then need to double that value as to account for the corresponding XOR cell.
        // This value must be held within a 64-bit value to prevent integer overflow from occurring in the
        // unlikely event that someone attempts to input u32::MAX bytes while running this software on a
        // 32-bit architecture.
        // This looks ugly, but I'm not sure that there is a better solution for now.
        let total_cells_needed = (1 + 4 + salt_bytes.len() as u64 + nonce_bytes.len() as u64 + total_ct_cells) * 2;
        log::debug!("Total cells needed = {}", total_cells_needed);

        if total_cells_needed > total_cells {
            return Err(Error::ImageInsufficientSpace);
        }

        // When seeding out PRNG, we cannot use the Argon2 hash for the positional random number generator
        // as we will need the salt, which will not be available when initially reading the data back from the file.
        let sha256_key_hash_bytes = Hashers::sha3_256_string(&final_key);
        let mut position_rand: ChaCha20Rng = StegaV1::u8_vec_to_seed(sha256_key_hash_bytes);

        // This random number generator will be used to create the XOR bytes.
        // This is separate from the positional RNG to allow the output files to vary, even with the input file and password.
        let mut data_rand: ChaCha20Rng = ChaCha20Rng::from_entropy();

        // This contains the list of every unused cell. Once a cell has been used, it is removed.
        // Initially I had planned to do with with a bitset, but it would require repeatedly checking
        // to see if the cell had been used, which could lower performance in cases where the total
        // number of available cells is close to the total number of cells needed to encode the data.
        // TODO: maybe convert this to a hashmap if it is too large and impacts performance?
        let mut available_cells: Vec<u64> = (0..total_cells).collect();

        // Select the next cell from the available list.
        let next_cell_index = position_rand.gen_range(0..available_cells.len());

        let cell_pixel_coordinates = StegaV1::get_cell_pixel_coordinates(&ref_image, next_cell_index);

        log::debug!("Cell {} contains pixels: {:?}", next_cell_index, cell_pixel_coordinates);

        //write_cell_pair

        /*let mut data: Vec<u8> = Vec::with_capacity(total_cells_needed);

        let version: u8 = 1;
        log::debug!("0b{:08b}", version);

        // We want to make sure that we convert everything into little Endian, to ensure that we can
        // operate cross-platform.
        let le_value = u8::to_le(version);
        log::debug!("0b{:08b}", le_value);

        // Push the version number to the data vector.
        data.push(version.to_le());

        // The maximum is set above, so this casting is safe.
        let plaintext_cell_bytes = u16::to_le_bytes(plaintext_bytes.len() as u16);
        data.push(plaintext_cell_bytes[0]);
        data.push(plaintext_cell_bytes[1]);

        //let mut i = 0;
        //while i <= 3 {
        //    println!("Is {} bit set? {:?}", &i, is_bit_set(&i, &le_value));
        //    i +=  1;
        //}*/

        // Test random number.
        //log::debug!("Has cell {:?} been used? {:?}", next_cell_index, !available_cells.contains(&next_cell_index));

        // Remove the cell from the list of available cells.
        //available_cells.remove(next_cell_index);
        //log::debug!("Has cell {:?} been used? {:?}", next_cell_index, !available_cells.contains(&next_cell_index));

        // Testing, testing, 1, 2, 3.
        let pixel = enc_image.get_pixel(0, 0);

        println!("rgba = {}, {}, {}, {}", pixel[0], pixel[1], pixel[2], pixel[3]);

        let new_pixel = image::Rgba([0, 0, 0, 255]);

        enc_image.put_pixel(0, 0, new_pixel);

        // Save the modified image.
        let r = enc_image.save(encoded_path);
        log::debug!("result = {:?}", r);

        Ok(())
    }

    fn decode(&mut self, original_path: &str, key: &str, encoded_path: &str) ->  Result<&str> {
        Ok("")
    }
}

impl Default for StegaV1 {
    fn default() -> Self {
        Self::new()
    }
}