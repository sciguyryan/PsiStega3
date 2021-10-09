#![crate_name = "psistega3_cli"]

use psistega3_core::codecs::codec::Codec;
use psistega3_core::codecs::v1::StegaV1;

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

    /*let iterations = 10;
    let start_0a = std::time::Instant::now();
    for _ in 0..=iterations {
        let e = stega.encode(input_img_path, password.clone(), &input, output_img_path);
    }
    let elapsed_0a = start_0a.elapsed();
    let per_item_0a = elapsed_0a / iterations as u32;
    println!(
        "threaded: {:.2?} in total, or {:.2?} per item.",
        elapsed_0a, per_item_0a
    );
    println!("{}", "-".repeat(32));

    return;*/

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
