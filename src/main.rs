pub mod steganography;
mod error;
mod version;
mod hashers;
mod utils;

use crate::steganography::Steganography;

use simple_logger::SimpleLogger;
use std::io::stdin;

fn main() {
    SimpleLogger::new().init().unwrap();

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

    // These strings are obviously just for testing.
    let input = "This is a test.";
    let password = "banana";

    let input_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b.jpg";
    let output_img_path = "D:\\GitHub\\PsiStega3\\test-images\\2.png";

    let mut stega = Steganography::new();

    let e = stega.encode(1, input_img_path, password, input, output_img_path);

	// Wait for user input.
    let mut input_string = String::new();
    stdin().read_line(&mut input_string).expect("Failed to read a line.");
}