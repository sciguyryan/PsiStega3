#![crate_name = "psistega3_cli"]
mod error;

use crate::error::{Error, Result};

use psistega3_core::codecs::codec::{Codec, Config};
use psistega3_core::codecs::v1::StegaV1;
use psistega3_core::version::*;

use simple_logger::SimpleLogger;
use std::{convert::TryFrom, env, io::stdin};

/// The prompt for confirming a yes/no option.
const CONFIRM_PROMPT: &str = "Are you sure you wish to enable this feature?";

//ooneporlygs

fn main() {
    SimpleLogger::new().init().unwrap();

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
                return;
            }
        }
        _ => {
            needs_codec = false;
        }
    }

    // Attempt to extract the codec version number.
    // No default codec needs to be implemented here, the if statement
    // below will always yield a valid codec.
    let mut codec: Box<dyn Codec>;
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
            return;
        }

        // The unwrap is safe here as we have verified the codec version
        // is valid.
        codec = get_codec_by_version(codec_version.unwrap());

        // Apply any settings that might have been specified.
        apply_codec_settings(&mut codec, &args[4..]);
    } else {
        codec = Box::new(StegaV1::default());
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
        return;
    }

    if args.last().unwrap() != "-unattended" {
        // Wait for user input.
        read_from_stdin();
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

    if args.contains(&String::from("--l")) || args.contains(&String::from("--locker")) {
        // We want to warn the user that enabling this option
        // render the data unrecoverable.
        let mut enabled = true;
        if args.last().unwrap() != "-unattended" {
            print!("WARNING: the file locker will render the encoded data unrecoverable if 5 or more attempts to decode the data are unsuccessful. ");
            enabled = read_confirm_from_stdin(CONFIRM_PROMPT);
        }

        codec.set_config_state(Config::Locker, enabled);
    }

    if args.contains(&String::from("--nf")) || args.contains(&String::from("--no-files")) {
        codec.set_config_state(Config::OutputFiles, false);
    }

    if args.contains(&String::from("--nn")) || args.contains(&String::from("--no-noise")) {
        codec.set_config_state(Config::NoiseLayer, false);
    }

    if args.contains(&String::from("--verbose")) {
        codec.set_config_state(Config::Verbose, true);
    }
}

/// Get an instance of the [`Codec`] for a specified [`Version`].
///
/// # Arguments
///
/// * `version` - The [`Codec`] [`Version`].
///
fn get_codec_by_version(version: Version) -> Box<dyn Codec> {
    match version {
        Version::V0x01 => Box::new(StegaV1::new()),
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
    let password = read_password(args)?;

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
    let password = read_password(args)?;

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
    let password = read_password_with_verify(args)?;

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
    let password = read_password_with_verify(args)?;

    match codec.encode_file(ref_image, password, input_file, output_image) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::Encoding(e.to_string())),
    }?;

    println!("The file has been successfully encoded.");
    Ok(())
}

/// Read a line of text from stdin.
fn read_from_stdin() -> String {
    let mut input_string = String::new();
    stdin()
        .read_line(&mut input_string)
        .expect("Failed to read a line.");
    input_string
}

/// Read a password.
/// This function will check the argument list first, then if no password was supplied a prompt will be offered.
fn read_password(args: &[String]) -> Result<String> {
    // First, attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_args(args);
    if password.is_none() {
        password = get_password("Password: ");
    }

    // If no password was supplied then an empty string
    // will be used as the password.
    // It isn't a safe password, but it is technically valid.
    if password.is_none() {
        password = Some("".to_string());
    }

    Ok(password.unwrap())
}

/// Read a yes/no confirmation from a stdin prompt.
fn read_confirm_from_stdin(prompt: &str) -> bool {
    println!("{}", prompt);
    let mut input_string = String::new();
    stdin()
        .read_line(&mut input_string)
        .expect("Failed to read a line.");

    let confirm = read_from_stdin().trim().to_lowercase();

    confirm == "y" || confirm == "yes"
}

/// Attempt to read a password argument from the argument list.
///
/// # Returns
///
/// If a password argument is specified, and if the password is not empty then a [`String`] [`Option`] will be returned,
/// otherwise a [`None`] will be returned.
///
fn read_password_args(args: &[String]) -> Option<String> {
    let password_arg = String::from("-p");
    if !args.contains(&password_arg) {
        return None;
    }

    let index = args.iter().position(|x| x == &password_arg).unwrap() + 1;

    // A password argument was specified, but no password was supplied.
    if args.len() <= index {
        return None;
    }

    Some(args[index].to_string())
}

/// Read a password, with verification.
/// This function will check the argument list first, then if no password was supplied a prompt will be offered.
fn read_password_with_verify(args: &[String]) -> Result<String> {
    // First, attempt to read the password from the supplied arguments.
    // If none was supplied, then we will offer a password input prompt.
    let mut password = read_password_args(args);
    if password.is_none() {
        let pwd_1 = get_password("Password: ");
        let pwd_2 = get_password("Confirm password: ");

        if pwd_1 == pwd_2 {
            password = pwd_1;
        } else {
            return Err(Error::PasswordMismatch);
        }
    }

    // If no password was supplied then an empty string
    // will be used as the password.
    // It isn't a safe password, but it is technically valid.
    if password.is_none() {
        password = Some("".to_string());
    }

    Ok(password.unwrap())
}

/// Write an [`Error`] message on screen and then abort the program.
///
/// # Arguments
///
/// * `error` - The [`Error`] to be displayed on screen.
///
pub fn show_abort_message(error: Error) {
    println!("Error: {}", error);
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
    println!("\t--l, --locker\t\tEnable file locker. This option will lock a file after 5 unsuccessful decryption attempts.");
    println!("\t--nn, --no-noise\tDisable the noise layer when encoding (better performance, lower security).");
    println!("\t--nf, --no-files\tDisable the creation of any output files.");
    //println!("\t--verbose\tEnable verbose mode.");
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
