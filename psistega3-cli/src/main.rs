#![crate_name = "psistega3_cli"]

use crate::codecs::v1::StegaV1;
use psistega3_core::codecs;

use codecs::codec::Codec;
use simple_logger::SimpleLogger;
use std::io::stdin;

//ookneporlygs

fn main() {
    SimpleLogger::new().init().unwrap();

    // These strings are obviously just for testing.
    let input = String::from("This is a test.");
    let password = String::from("banana1234");

    let input_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b.png";
    let output_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b2.png";

    let mut stega = StegaV1::new(true);

    log::debug!("{}", "-".repeat(32));
    log::debug!("Starting encoding...");
    let e = stega.encode(input_img_path, password.clone(), &input, output_img_path);
    log::debug!("Result = {:?}", e);
    log::debug!("{}", "-".repeat(32));
    log::debug!("Starting decoding...");
    let d = stega.decode(input_img_path, password, output_img_path);
    log::debug!("Result = {:?}", d);
    log::debug!("{}", "-".repeat(32));

    // Wait for user input.
    let mut input_string = String::new();
    stdin()
        .read_line(&mut input_string)
        .expect("Failed to read a line.");
}
