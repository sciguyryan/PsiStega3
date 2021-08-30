mod steganography;
mod error;
mod version;

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

use argon2::{Argon2, Version};

use core::fmt::Write;

use image::{DynamicImage, GenericImage, GenericImageView};

use sha3::{Digest, Sha3_256, Sha3_512};

use std::convert::TryFrom;

use std::io::prelude::*;
use std::io::stdin;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, OsRng};
use rand::prelude::*;

const ARGON_T_COST: u32 = 6;
const ARGON_P_COST: u32 = 3;
const ARGON_M_COST: u32 = 4096;

fn main() {
    // Generate a hash of the input file.
    // Generate a random pair from the hash.
    // Generate a cryptographic random seed.
    // Generate 8 byte values (0 - 255). (Or, should a user-specified password be used here instead?)
    // Write the random bytes into the output image file in a random cell), add the cell numbers to a list to ensure they are not reused.
    // Generate a new hash by combining the random data and the original file hash.
    // Generate a random pair from the new hash.
    // (Encrypt the input string with a user-specified password?)
    // Convert the input string into a byte array.
    // For each byte, create a random byte. This byte will be the XOR value for the byte.
    // Write the byte and the XOR byte into the output image file (in a random cell), add the cell numbers to a list to ensure they are not reused.
    // Fill the unused cells with a random noise to ensure that they cannot be differentiated.

    let input_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b.jpg";

    let mut img = image::open(input_img_path).unwrap();

    let (width, height) =  img.dimensions();
    println!("dimensions {:?}", img.dimensions());

    // The total number of pixels must be divisible by two.
    let total_pixels = width * height;
    if total_pixels % 2 > 0 {
        println!("Total number of pixels in the target image must be divisible by 2.");
        return;
    }

    // Each cell is 2x1 pixels in size.
    let total_cells: usize = total_pixels as usize / 2;
    println!("Total available cells = {:?}", &total_cells);

    //*************************** SHA3-256 input file hashing ***************************//
    let file_hash_bytes = sha512_file(input_img_path);
    let file_hash_string = u8_array_to_hex(&file_hash_bytes).unwrap(); // This is internal and cannot fail.

    println!("File hash length: {:?}" , file_hash_bytes.len());
    println!("File hash: {}", file_hash_string);
    println!("-----------------------------------------------");
    //*************************** SHA3-256 input file hashing ***************************//


    //*************************** Hashing ***************************//
    let input = "This is a test.";
    let input_bytes = input.as_bytes();
    let password = "banana";

    // The key for the encryption is the sha3-512 hash of the input image file combined with the plaintext password string.
    let mut final_key: String = password.to_owned();
    final_key.push_str(&file_hash_string);

    let final_key_bytes = final_key.as_bytes();

    // We cannot use the Argon2 hash for the positional random number generator because
    // we will need access to the Argon2 hash salt, which will not be available when reading the data back from the file.
    let sha256_key_hash_bytes = sha256_string(&final_key);

    // Generate a random salt for the Argon2 hashing function.
    let mut salt_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt_bytes);

    let mut builder = argon2::ParamsBuilder::new();

    // TODO: handle these panics better.
    if builder.m_cost(ARGON_M_COST).is_err() {
        panic!("Error applying Argon2 memory cost parameter.")
    };
    if builder.p_cost(ARGON_P_COST).is_err() {
        panic!("Error applying Argon2 parallelism cost parameter.")
    };
    if builder.p_cost(ARGON_T_COST).is_err() {
        panic!("Error applying Argon2 T_COST parameter.")
    };

    // The parameter builder will fail if any of the params are incorrect, this unwrap should be safe as a result.
    let params = builder.params().unwrap();

    let hasher =  Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // The AES-256 algorithm uses a key of 256 bits (32 bytes).
    let mut key_bytes = [0u8; 32];
    if hasher.hash_password_into(final_key_bytes, &salt_bytes, &mut key_bytes).is_ok() {
        println!("Key hash bytes: {:?}", key_bytes);
    } else {
        println!("Error creating password hash.");
        return;
    }

    let hex_key_hash =  u8_array_to_hex(&key_bytes).unwrap(); // This is internal and cannot fail.
    println!("Hex key hash: {}", hex_key_hash);
    //*************************** Hashing ***************************//;


    //*************************** AES-256 encryption ***************************//
    let key = Key::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a unique random 96-bit  (12 byte) nonce (IV).
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_bytes = cipher.encrypt(nonce, input_bytes.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    println!("Ciphertext bytes: {:?}", ciphertext_bytes);

    let plaintext_bytes = cipher.decrypt(nonce, ciphertext_bytes.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    println!("Plaintext bytes: {:?}", plaintext_bytes);

    // This code will not be kept around, so we can safely use clone here.
    let plaintext_str = match String::from_utf8(plaintext_bytes.clone()) {
        Ok(s) => s,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    println!("Plaintext string: {}", plaintext_str);
    //*************************** AES-256 encryption ***************************//


    //*************************** RNG stuff ***************************//
    // 1 cell for the version (treated specially as a raw binary literal)
    // 4 cells for the total number of ciphertext cells  (treated as a raw binary literal) - this gives a maximum of 0b1111111111111111 cells. This equates to 4,294,967,295 bytes, as 1 byte is stored per cell.
    // the salt, the nonce and the ciphertext.
    // 2 times the above as we need to account for the XOR cell too.
    let total_cells_needed = (1 + 4 + salt_bytes.len() + nonce_bytes.len() + ciphertext_bytes.len()) * 2;
    println!("Total cells needed = {:?}", total_cells_needed);

    if total_cells_needed > 0b1111_1111_1111_1111 {
        println!("Data exceeds maximum permitted storage capacity.");
        return;
    }

    if total_cells_needed > total_cells {
        println!("Insufficient pixels within the image to store the specified data.");
        return;
    }

    // We will only use the first 32 bytes of the hash for the seed here.
    // We will need to use the SHA-512 hash bytes here as Argon2 will not create a reproducible RNG seed.
    // TODO: maybe find a 64-bit seedable random number generator?
    let mut position_rand: ChaCha20Rng = u8_vec_to_seed(sha256_key_hash_bytes);

    // This random number generator will be used to create the XOR byte values.
    // This is separate from the positional RNG to allow the output files to vary, even with the same seed and password.
    let mut xor_rand: ChaCha20Rng = ChaCha20Rng::from_entropy();
    //*************************** RNG stuff ***************************//

    //*************************** Cell status testing ***************************//
    // The vector which contains the list of every available cell. When a cell has been used it is removed from this vector.
    let mut available_cells: Vec<usize> = Vec::with_capacity(total_cells);
    for i in 0..total_cells {
        available_cells.push(i);
    }

    // Select the next cell from the available  list.
    let mut next_cell_index = position_rand.gen_range(0..available_cells.len());

    let mut data: Vec<u8> = Vec::with_capacity(total_cells_needed);

    let version: u8 = 1;
    println!("0b{:08b}", version);

    // We want to make sure that we convert everything into little Endian, to ensure that we can
    // operate cross-platform.
    let le_value = u8::to_le(version);
    println!("0b{:08b}", le_value);

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
    //}

    // Test random number.
    println!("Has cell {:?} been used? {:?}", next_cell_index, !available_cells.contains(&next_cell_index));

    // Remove the cell from the list of available cells.
    available_cells.remove(next_cell_index);
    println!("Has cell {:?} been used? {:?}", next_cell_index, !available_cells.contains(&next_cell_index));
    //*************************** Cell status testing ***************************//

    // Testing, testing, 1, 2, 3.
    let pixel = img.get_pixel(0, 0);

    println!("rgba = {}, {}, {}, {}", pixel[0], pixel[1], pixel[2], pixel[3]);

    let new_pixel = image::Rgba([0, 0, 0, 0]);

    img.put_pixel(0, 0, new_pixel);

    let r = img.save("D:\\GitHub\\PsiStega3\\test-images\\2.png");

    println!("result = {:?}", r);

	// Wait for user input.
    let mut input_string = String::new();
    stdin().read_line(&mut input_string).expect("Failed to read a line.");
}

fn write_data_to_image() {
}

fn is_bit_set(bit: &u8, value: &u8) -> bool {
    (value & (1 << bit)) == 1
}

// TODO: remove the error conditions, if they are slowing things down.
fn u8_array_to_hex(arr: &[u8]) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(2 * arr.len());
    for byte in arr {
        if let Err(e)  = write!(str, "{:02X}", byte) {
            return Err(e)
        }
    }
    Ok(str)
}

// TODO: remove the error conditions, if they are slowing things down.
fn u8_to_binary(byte: &u8) -> Result<String, std::fmt::Error> {
    let mut str = String::with_capacity(8);
    if let Err(e)  = write!(str, "{:08b}", byte) {
        return Err(e)
    }
    Ok(str)
}


fn sha512_file(path: &str) -> Vec<u8> {
    let mut hasher = Sha3_512::new();

    // The file will automatically be closed when it goes out of scope.
    let mut f = std::fs::File::open(path).unwrap();
    let mut buffer = [0u8; 16384];

    loop {
        let n = f.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    hasher.finalize().to_vec()
}

fn sha256_string(str: &str) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(&str);
    hasher.finalize().to_vec()
}

fn u8_vec_to_seed<R: SeedableRng<Seed = [u8; 32]>>(bytes: Vec<u8>) -> R {
    assert!(bytes.len() == 32, "Byte vector is not 32 bytes (256-bits) in length.");
    let arr = <[u8; 32]>::try_from(bytes).unwrap();

    R::from_seed(arr)
}