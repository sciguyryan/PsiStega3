#![crate_name = "psistega3_cli"]
mod error;
mod file_attempts;
mod utils;

use crate::error::{Error, Result};

use psistega3_core::codecs::codec::{Codec, Config};
use psistega3_core::codecs::v1::StegaV1;
use psistega3_core::version::*;

use simple_logger::SimpleLogger;
use std::{convert::TryFrom, env, io::stdin};

//ookneporlygs

fn main() {
    if let Err(e) = utils::create_data_file() {
        show_abort_message(e);
    }

    SimpleLogger::new().init().unwrap();

    //println!("{:?}", utils::get_data_file_path());

    let mut args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        show_help();
        return;
    }

    // Automatically convert any command-type arguments to lowercase.
    for arg in args.iter_mut() {
        if arg.starts_with('-') {
            *arg = arg.to_lowercase();
        }
    }

    // The action argument.
    let action = &args[1];

    // There must be at least 6 arguments in most circumstances.
    let mut needs_codec = true;
    match action.as_str() {
        "-e" | "-encrypt" | "-d" | "-decrypt" | "-ef" | "-encrypt-file" | "-df"
        | "-decrypt-file" => {
            if args.len() < 6 {
                show_abort_message(Error::InsufficientArguments);
            }
        }
        _ => {
            needs_codec = false;
        }
    }

    // Attempt to extract the codec version number.
    let mut codec: Box<dyn Codec> = Box::new(StegaV1::default());
    if needs_codec {
        let mut codec_version: Option<Version> = None;
        if &args[2] == "-v" {
            let version = &args[3];
            if let Ok(v) = version.parse::<u8>() {
                if let Ok(cv) = Version::try_from(v) {
                    codec_version = Some(cv);
                }
            }
        }

        if codec_version.is_none() {
            show_abort_message(Error::InvalidVersion);
        }

        // The unwrap is safe here as we have verified the codec version
        // is valid.
        codec = get_codec_by_version(codec_version.unwrap());

        // Apply any settings that might have been specified.
        apply_codec_settings(&mut codec, &args[4..]);
    }

    // Execute the requested action with the provided arguments.
    let result = match action.as_str() {
        "-e" | "-encrypt" => handle_encode(&args[4..], &mut codec),
        "-d" | "-decrypt" => handle_decode(&args[4..], &mut codec),
        "-ef" | "-encrypt-file" => handle_encode_file(&args[4..], &mut codec),
        "-df" | "-decrypt-file" => handle_decode_file(&args[4..], &mut codec),
        "-examples" => {
            show_examples();
            Ok(())
        }
        _ => {
            show_help();
            Ok(())
        }
    };

    // If we encountered an error then display that error to the console.
    if let Err(e) = result {
        show_abort_message(e);
    }

    let arg_len = &args.len();
    if &args[*arg_len - 1] != "-auto-exit" {
        // Wait for user input.
        let mut input_string = String::new();
        stdin()
            .read_line(&mut input_string)
            .expect("Failed to read a line.");
    }
}

/// Apply any specified coded settings.
///
/// # Arguments
///
/// * `codec` - The instance of the [`Codec`] to be used for this command.
/// * `args` - A list of arguments relevant for this command.
///
fn apply_codec_settings(codec: &mut Box<dyn Codec>, args: &[String]) {
    if args.contains(&String::from("--fv")) || args.contains(&String::from("--fast-variance")) {
        codec.set_config_state(Config::FastVariance, true);
    }

    if args.contains(&String::from("--nf")) || args.contains(&String::from("--no-files")) {
        codec.set_config_state(Config::OutputFiles, false);
    }

    if args.contains(&String::from("--nn")) || args.contains(&String::from("--no-noise")) {
        codec.set_config_state(Config::NoiseLayer, false);
    }

    //if args.contains(&String::from("--verbose")) {
    //    codec.set_config_state(Config::Verbose, true);
    //}
}

/// Get an instance of the [`Codec`] for a specified [`Version`].
///
/// # Arguments
///
/// * `key` - The [`Codec`] [`Version`].
///
fn get_codec_by_version(version: Version) -> Box<dyn Codec> {
    match version {
        Version::V0x01 => Box::new(StegaV1::default()),
    }
}

/// Prompt the user to input a password.
///
/// # Arguments
///
/// * `prompt` - The password prompt string.
///
fn get_password(prompt: &str) -> Option<String> {
    println!("{}", prompt);
    match rpassword::read_password() {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

/// Handle a text decode command.
///
/// # Arguments
///
/// * `args` - A list of arguments relevant for this command.
/// * `codec` - The instance of the [`Codec`] to be used for this command.
///
fn handle_decode(args: &[String], codec: &mut Box<dyn Codec>) -> Result<()> {
    // Reference image path, encoded image path.
    if args.len() < 2 {
        return Err(Error::InsufficientArguments);
    }

    let ref_image = &args[0];
    let enc_image = &args[1];

    // Attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_from_args(args);
    if password.is_none() {
        password = read_password();
        if password.is_none() {
            return Err(Error::NoPassword);
        }
    }

    let password = password.unwrap();

    // Attempt to decode the data.
    let plaintext = match codec.decode(ref_image, password, enc_image) {
        Ok(s) => Ok(s),
        Err(e) => Err(Error::Decoding(e.to_string())),
    }?;

    println!("{}", "-".repeat(32));
    if plaintext.contains('�') {
        println!("One or more unprintable characters were detected in the decoded data. This could mean the data is binary data and cannot be printed here.");
        println!("Please try decoding the data using the -df command instead.");
    } else {
        // Output the decoded string to the console.
        println!("{}", plaintext);
    }

    Ok(())
}

/// Handle a file decode command.
///
/// # Arguments
///
/// * `args` - A list of arguments relevant for this command.
/// * `codec` - The instance of the [`Codec`] to be used for this command.
///
fn handle_decode_file(args: &[String], codec: &mut Box<dyn Codec>) -> Result<()> {
    // Reference image path, encoded image path, output file path.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    let ref_image = &args[0];
    let enc_image = &args[1];
    let output_file_path = &args[2];

    // Attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_from_args(args);
    if password.is_none() {
        password = read_password();
        if password.is_none() {
            return Err(Error::NoPassword);
        }
    }

    let password = password.unwrap();

    // Attempt to decode the data.
    match codec.decode_file(ref_image, password, enc_image, output_file_path) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::Decoding(e.to_string())),
    }?;

    // Output the decoded string to the console.
    println!("The file has been successfully decoded to the specified output path.");

    Ok(())
}

/// Handle a text encode command.
///
/// # Arguments
///
/// * `args` - A list of arguments relevant for this command.
/// * `codec` - The instance of the [`Codec`] to be used for this command.
///
fn handle_encode(args: &[String], codec: &mut Box<dyn Codec>) -> Result<()> {
    // Reference image path, output image path, text.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    let ref_image = &args[0];
    let output_image = &args[1];
    let text = &args[2];

    // Attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_from_args(args);
    if password.is_none() {
        password = read_password_with_verify();
        if password.is_none() {
            return Err(Error::PasswordMismatch);
        }
    }

    let password = password.unwrap();

    match codec.encode(ref_image, password, text, output_image) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::Encoding(e.to_string())),
    }?;

    println!("The text has been successfully encoded.");
    Ok(())
}

/// Handle a file encode command.
///
/// # Arguments
///
/// * `args` - A list of arguments relevant for this command.
/// * `codec` - The instance of the [`Codec`] to be used for this command.
///
fn handle_encode_file(args: &[String], codec: &mut Box<dyn Codec>) -> Result<()> {
    // Reference image path, output image path, input file path.
    if args.len() < 3 {
        return Err(Error::InsufficientArguments);
    }

    let ref_image = &args[0];
    let output_image = &args[1];
    let input_file = &args[2];

    // Attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_from_args(args);
    if password.is_none() {
        password = read_password_with_verify();
        if password.is_none() {
            return Err(Error::PasswordMismatch);
        }
    }

    let password = password.unwrap();

    match codec.encode_file(ref_image, password, input_file, output_image) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::Encoding(e.to_string())),
    }?;

    println!("The file has been successfully encoded.");
    Ok(())
}

/// Read a password from the terminal.
fn read_password() -> Option<String> {
    get_password("Password: ")
}

/// Prompt the user for a password, with verification.
///
/// # Returns
///
/// If the two passwords are the same then a [`String`] [`Option`] will be returned,
/// otherwise a [`None`] will be returned.
///
fn read_password_with_verify() -> Option<String> {
    let pwd_1 = get_password("Password: ");
    let pwd_2 = get_password("Confirm password: ");

    if pwd_1.is_some() && pwd_1 == pwd_2 {
        return pwd_1;
    }

    None
}

/// Attempt to read a password argument from the argument list.
///
/// # Returns
///
/// If a password argument is specified, and if the password is not empty then a [`String`] [`Option`] will be returned,
/// otherwise a [`None`] will be returned.
///
fn read_password_from_args(args: &[String]) -> Option<String> {
    let password_arg = String::from("-p");
    if !args.contains(&password_arg) {
        return None;
    }

    let mut index = args.iter().position(|x| x == &password_arg).unwrap();
    index += 1;

    // A password argument was specified, but no password was supplied.
    if args.len() <= index {
        return None;
    }

    Some(args[index].to_string())
}

/// Write some basic help information on screen.
fn show_help() {
    println!("A steganography tool written in Rust.");
    println!();
    println!("USAGE:");
    println!("\tpsistega3 ACTION VERSION PARAMS [OPTIONS]");
    println!();
    println!("ACTION:");
    println!("\t-e, -E\t\t\tEncode a string into a target image.");
    println!("\t-d, -D\t\t\tDecode a string from a target image.");
    println!("\t-ef, -EF\t\tEncode a file into a target image.");
    println!("\t-df, -DF\t\tDecode a file from a target image.");
    println!();
    println!("OPTIONS:");
    println!("\t--fv, --fast-variance\tEnable the fast variance encoding mode (better performance, lower security).");
    println!("\t--nn, --no-noise\t\tDisable the noise layer when encoding (better performance, lower security).");
    println!("\t--nf, --no-files\t\tDisable the creation of any output files.");
    //println!("\t--verbose\t\tEnable verbose mode.");
    println!();
    println!("Please use -examples to display some example commands.");
}

/// Write some example commands on screen.
fn show_examples() {
    let split = "-".repeat(32);
    println!("{}", split);
    println!(
        "psistega3 -e -v 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"A very important message.\""
    );
    println!();
    println!("This command will attempt to encode a string into the reference image.");
    println!("You will be prompted twice for a password after executing this command.");
    println!("{}", split);
    println!("psistega3 -d -v 1 \"C:\\reference.png\" \"C:\\encoded.png\"");
    println!();
    println!("You will be prompted for a password after executing this command.");
    println!("If any data was successfully decoded then it will be displayed on screen.");
    println!("{}", split);
    println!(
        "psistega3 -ef -v 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"C:\\input_file_path.foo\""
    );
    println!();
    println!("This command will attempt to encode a file into the reference image.");
    println!("You will be prompted twice for a password after executing this command.");
    println!("{}", split);
    println!(
        "psistega3 -df -v 1 \"C:\\reference.png\" \"C:\\encoded.png\" \"C:\\output_file_path.foo\""
    );
    println!();
    println!("You will be prompted for a password after executing this command.");
    println!(
        "If any data was successfully decoded then it will be written to the output file path."
    );
    println!("{}", split);
}

/// Write an [`Error`] message on screen and then abort the program.
///
/// # Arguments
///
/// * `error` - The [`Error`] to be displayed on screen.
///
fn show_abort_message(error: Error) {
    println!("Error: {}", error);
    std::process::exit(0);
}
