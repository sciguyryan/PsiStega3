mod codecs;
mod error;
mod hashers;
mod image_wrapper;
mod utils;
mod version;

use crate::codecs::v1;

use codecs::codec::Codec;
use simple_logger::SimpleLogger;
use std::io::stdin;

fn main() {
    SimpleLogger::new().init().unwrap();

    // These strings are obviously just for testing.
    let input = "This is a test.";
    let password = "banana123";

    let input_img_path = "D:\\GitHub\\PsiStega3\\test-images\\i.png";
    let output_img_path = "D:\\GitHub\\PsiStega3\\test-images\\i2.png";

    let mut stega = v1::StegaV1::new();

    log::debug!("{}", "-".repeat(32));
    log::debug!("Starting encoding...");
    let e = stega.encode(input_img_path, password, input, output_img_path);
    log::debug!("{}", "-".repeat(32));
    log::debug!("Starting decoding...");
    let s = stega.decode(input_img_path, password, output_img_path);

    // Wait for user input.
    let mut input_string = String::new();
    stdin()
        .read_line(&mut input_string)
        .expect("Failed to read a line.");
}
