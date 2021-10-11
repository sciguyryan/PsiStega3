#![crate_name = "psistega3_cli"]
mod error;

use crate::error::{Error, Result};

use psistega3_core::codecs::codec::Codec;
use psistega3_core::codecs::v1::StegaV1;
//use psistega3_core::error::{Error};
use psistega3_core::version::*;

use simple_logger::SimpleLogger;
use std::{convert::TryFrom, env, io::stdin};

//ookneporlygs

fn main() {
    SimpleLogger::new().init().unwrap();

    let mut args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        show_help();
        return;
    }

    // Automatically convert any command arguments to lowercase.
    for arg in args.iter_mut() {
        if arg.contains('-') {
            *arg = arg.to_lowercase();
        }
    }

    // The action argument.
    let mut action = &args[1];

    // If we should enable verbose mode.
    let mut verbose = false;

    // If the first argument is -v or -verbose then we need to shift the action
    // argument index by one.
    if action == "-verbose" || action == "-v" {
        // There must be at least 7 arguments.
        if args.len() < 7 {
            show_abort_error(Error::InsufficientArguments);
        }

        verbose = true;
        action = &args[2];
    } else if action == "-examples" {
        show_examples();
        return;
    } else {
        // There must be at least 6 arguments.
        if args.len() < 6 {
            show_abort_error(Error::InsufficientArguments);
        }
    }

    let mut index = if verbose { 3 } else { 2 };

    // Attempt to extract the codec version number.
    let mut codec_version: Option<Version> = None;
    if &args[index] == "-version" {
        let version = &args[index + 1];
        if let Ok(v) = version.parse::<u8>() {
            if let Ok(cv) = Version::try_from(v) {
                codec_version = Some(cv);
            }
        }
    }

    if codec_version.is_none() {
        show_abort_error(Error::InvalidVersion);
    }

    // Skip over the version arguments.
    index += 2;

    // This shadowing is safe since we have verified that we
    // have a valid version number above.
    let codec_version = codec_version.unwrap();

    // Parge the arguments for the requested action.
    let result = match action.as_str() {
        "-e" | "-encrypt" => handle_encrypt(&args[index..], codec_version, verbose),
        "-d" | "-decrypt" => handle_decrypt(&args[index..], codec_version, verbose),
        "-ef" | "-encrypt-file" => handle_file_encrypt(&args[index..], codec_version, verbose),
        "-df" | "-decrypt-file" => handle_file_decrypt(&args[index..], codec_version, verbose),
        _ => {
            show_help();
            Ok(())
        }
    };

    println!("{:?}", result);

    return;

    // These strings are obviously just for testing.
    let input = String::from("This is a test.");
    let password = String::from("banana1234");

    let input_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b.png";
    let output_img_path = "D:\\GitHub\\PsiStega3\\test-images\\b2.png";

    let mut stega = StegaV1::default();

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

fn handle_encrypt(args: &[String], ver: Version, verbose: bool) -> Result<()> {
    // Reference image path, output image path, text.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    println!("{:?}", args);
    Ok(())
}

fn handle_file_encrypt(args: &[String], ver: Version, verbose: bool) -> Result<()> {
    // Reference image path, output image path, input file path.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    println!("{:?}", args);
    Ok(())
}

fn handle_decrypt(args: &[String], ver: Version, verbose: bool) -> Result<()> {
    // Reference image path, encoded image path.
    if args.len() < 2 {
        return Err(Error::InsufficientArguments);
    }

    println!("{:?}", args);
    Ok(())
}

fn handle_file_decrypt(args: &[String], ver: Version, verbose: bool) -> Result<()> {
    // Reference image path, encoded image path, output file path.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    println!("{:?}", args);
    Ok(())
}

fn show_help() {
    println!("A stegranography tool.");
    println!();
    println!("USAGE:");
    println!("\tpsistega3 [VERBOSE] [ACTION] [VERSION] [PARAMS]");
    println!();
    println!("VERBOSE:");
    println!("\t-v, -V\t\t\tEnable verbose mode.");
    println!();
    println!("ACTION:");
    println!("\t-e, -E\t\t\tEncode a string into a target image.");
    println!("\t-d, -D\t\t\tDecode a string from a target image.");
    println!("\t-ef, -EF\t\tEncode a file into a target image.");
    println!("\t-df, -DF\t\tDecode a file from a target image.");
    println!();
    println!("Please use -examples to display some example commands.");
}

fn show_examples() {
    println!("{}", "-".repeat(32));
    println!("psistega3 -e -version 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"A very important message.\"");
    println!();
    println!("This command will attempt to encode a string into the reference image.");
    println!("You will be prompted twice for a password after executing this command.");
    println!("{}", "-".repeat(32));
    println!("psistega3 -d -version 1 \"C:\\reference.png\" \"C:\\encoded.png\"");
    println!();
    println!("You will be prompted for a password after executing this command.");
    println!("If any data was successfully decoded then it will be displayed on screen.");
    println!("{}", "-".repeat(32));
    println!("psistega3 -ef -version 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"C:\\input_file_path.foo\"");
    println!();
    println!("This command will attempt to encode a file into the reference image.");
    println!("You will be prompted twice for a password after executing this command.");
    println!("{}", "-".repeat(32));
    println!("psistega3 -df -version 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"C:\\output_file_path.foo\"");
    println!();
    println!("You will be prompted for a password after executing this command.");
    println!(
        "If any data was successfully decoded then it will be written to the output file path."
    );
    println!("{}", "-".repeat(32));
}

fn show_abort_error(error: Error) {
    println!("{}", error);
    std::process::exit(0);
}
