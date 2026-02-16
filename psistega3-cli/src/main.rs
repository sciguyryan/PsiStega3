#![crate_name = "psistega3_cli"]
mod error;
use crate::error::{Error, Result};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "secret-fun")]
use crossterm::terminal::size;
use psistega3_core::codecs::{
    codec::{Codec, ConfigFlags, ConfigParams},
    v2::StegaV2,
    v3::StegaV3,
};
#[cfg(feature = "secret-fun")]
use sha3::{Digest, Sha3_512};
use simple_logger::SimpleLogger;
use std::io::stdin;

/// The prompt for confirming a yes/no option.
const CONFIRM_PROMPT: &str = "Are you sure you wish to enable this feature?";

#[cfg(feature = "secret-fun")]
/// It's an easter egg... didn't you read the name?
const EASTER_EGG_ENCODED: [u8; 27] = [
    236, 167, 178, 205, 108, 248, 194, 77, 10, 6, 135, 238, 116, 103, 39, 232, 230, 171, 109, 120,
    76, 196, 215, 28, 61, 205, 80,
];

/// Supported codec versions for encoding.
#[derive(Clone, Debug, ValueEnum)]
enum Version {
    /// Version 2 codec.
    V2,
    /// Version 3 codec (default, recommended).
    V3,
}

/// A steganography tool written in Rust
#[derive(Parser)]
#[command(name = "psistega3")]
#[command(about = "A steganography tool written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable unattended mode (no user prompts).
    #[arg(long, global = true)]
    unattended: bool,
    /// Enable verbose output.
    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode a string into a target image.
    #[command(visible_alias = "e")]
    Encode {
        /// Reference image path.
        #[arg(value_name = "REF_IMAGE")]
        ref_image: String,
        /// Output image path.
        #[arg(value_name = "OUTPUT_IMAGE")]
        output_image: String,
        /// Text to encode.
        #[arg(value_name = "TEXT")]
        text: String,
        /// Password (if not provided, you will be prompted)
        /// Providing passwords this way is not advised.
        #[arg(short, long)]
        password: Option<String>,
        /// Codec version to use (v2 or v3, default: v3).
        #[arg(short = 'v', long, value_enum, default_value = "v3")]
        version: Version,
        /// Enable file locker (locks after 5 failed attempts) [v2 only].
        #[arg(short = 'l', long)]
        locker: bool,
        /// Disable noise layer (better performance, lower security).
        #[arg(long)]
        no_noise: bool,
        /// Disable creation of output files.
        #[arg(long)]
        no_files: bool,
        /// Lock file after one successful read [v2 only].
        #[arg(long)]
        read_once: bool,
        /// Argon2 time cost parameter (iterations) [v3 only].
        #[arg(long)]
        t_cost: Option<u32>,
        /// Argon2 parallelism cost parameter (threads) [v3 only].
        #[arg(long)]
        p_cost: Option<u32>,
        /// Argon2 memory cost parameter (KiB) [v3 only].
        #[arg(long)]
        m_cost: Option<u32>,
    },
    /// Decode a string from a target image.
    #[command(visible_alias = "d")]
    Decode {
        /// Reference image path.
        #[arg(value_name = "REF_IMAGE")]
        ref_image: String,
        /// Encoded image path.
        #[arg(value_name = "ENCODED_IMAGE")]
        encoded_image: String,
        /// Password (if not provided, you will be prompted).
        /// Providing passwords this way is not advised.
        #[arg(short, long)]
        password: Option<String>,
        /// Disable creation of output files.
        #[arg(long)]
        no_files: bool,
        /// Argon2 time cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        t_cost: Option<u32>,
        /// Argon2 parallelism cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        p_cost: Option<u32>,
        /// Argon2 memory cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        m_cost: Option<u32>,
    },
    /// Encode a file into a target image.
    #[command(visible_alias = "ef")]
    EncodeFile {
        /// Reference image path.
        #[arg(value_name = "REF_IMAGE")]
        ref_image: String,
        /// Output image path.
        #[arg(value_name = "OUTPUT_IMAGE")]
        output_image: String,
        /// Input file path to encode.
        #[arg(value_name = "INPUT_FILE")]
        input_file: String,
        /// Password (if not provided, you will be prompted).
        /// Providing passwords this way is not advised.
        #[arg(short, long)]
        password: Option<String>,
        /// Codec version to use (v2 or v3, default: v3).
        #[arg(short = 'v', long, value_enum, default_value = "v3")]
        version: Version,
        /// Enable file locker (locks after 5 failed attempts) [v2 only].
        #[arg(short = 'l', long)]
        locker: bool,
        /// Disable noise layer (better performance, lower security).
        #[arg(long)]
        no_noise: bool,
        /// Disable creation of output files.
        #[arg(long)]
        no_files: bool,
        /// Lock file after one successful read [v2 only].
        #[arg(long)]
        read_once: bool,
        /// Argon2 time cost parameter (iterations) [v3 only].
        #[arg(long)]
        t_cost: Option<u32>,
        /// Argon2 parallelism cost parameter (threads) [v3 only].
        #[arg(long)]
        p_cost: Option<u32>,
        /// Argon2 memory cost parameter (KiB) [v3 only].
        #[arg(long)]
        m_cost: Option<u32>,
    },
    /// Decode a file from a target image.
    #[command(visible_alias = "df")]
    DecodeFile {
        /// Reference image path.
        #[arg(value_name = "REF_IMAGE")]
        ref_image: String,
        /// Encoded image path.
        #[arg(value_name = "ENCODED_IMAGE")]
        encoded_image: String,
        /// Output file path for decoded data.
        #[arg(value_name = "OUTPUT_FILE")]
        output_file: String,
        /// Password (if not provided, you will be prompted).
        /// Providing passwords this way is not advised.
        #[arg(short, long)]
        password: Option<String>,
        /// Disable creation of output files.
        #[arg(long)]
        no_files: bool,
        /// Argon2 time cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        t_cost: Option<u32>,
        /// Argon2 parallelism cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        p_cost: Option<u32>,
        /// Argon2 memory cost parameter (must match encoding) [v3 only].
        #[arg(long)]
        m_cost: Option<u32>,
    },
    /// Show example commands
    Examples,
    /// Do you know the secret?
    #[cfg(feature = "secret-fun")]
    Secret {
        #[arg(value_name = "SECRET")]
        the_secret: String,
    },
}

fn main() {
    SimpleLogger::new().init().unwrap();
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encode {
            ref_image,
            output_image,
            text,
            password,
            version,
            locker,
            no_noise,
            no_files,
            read_once,
            t_cost,
            p_cost,
            m_cost,
        } => {
            let mut codec = create_codec(&version);
            check_version_compatibility(&version, locker, read_once);

            apply_encode_settings(
                &mut codec,
                &version,
                locker,
                no_noise,
                no_files,
                read_once,
                t_cost,
                p_cost,
                m_cost,
                cli.verbose,
                cli.unattended,
            );

            let password = match get_password_with_verify(password, cli.unattended) {
                Ok(p) => p,
                Err(e) => return show_abort_message(e),
            };
            handle_encode(&ref_image, &output_image, &text, password, &mut codec)
        }

        Commands::EncodeFile {
            ref_image,
            output_image,
            input_file,
            password,
            version,
            locker,
            no_noise,
            no_files,
            read_once,
            t_cost,
            p_cost,
            m_cost,
        } => {
            let mut codec = create_codec(&version);
            check_version_compatibility(&version, locker, read_once);

            apply_encode_settings(
                &mut codec,
                &version,
                locker,
                no_noise,
                no_files,
                read_once,
                t_cost,
                p_cost,
                m_cost,
                cli.verbose,
                cli.unattended,
            );

            let password = match get_password_with_verify(password, cli.unattended) {
                Ok(p) => p,
                Err(e) => return show_abort_message(e),
            };
            handle_encode_file(&ref_image, &output_image, &input_file, password, &mut codec)
        }

        Commands::Decode {
            ref_image,
            encoded_image,
            password,
            no_files,
            t_cost,
            p_cost,
            m_cost,
        } => {
            let password = match get_password_with_verify(password, cli.unattended) {
                Ok(p) => p,
                Err(e) => return show_abort_message(e),
            };
            handle_decode_with_optional_version(
                &ref_image,
                &encoded_image,
                password,
                no_files,
                cli.verbose,
                None,
                t_cost,
                p_cost,
                m_cost,
            )
        }

        Commands::DecodeFile {
            ref_image,
            encoded_image,
            output_file,
            password,
            no_files,
            t_cost,
            p_cost,
            m_cost,
        } => {
            let password = match get_password_with_verify(password, cli.unattended) {
                Ok(p) => p,
                Err(e) => return show_abort_message(e),
            };
            handle_decode_file_with_optional_version(
                &ref_image,
                &encoded_image,
                &output_file,
                password,
                no_files,
                cli.verbose,
                None,
                t_cost,
                p_cost,
                m_cost,
            )
        }

        Commands::Examples => {
            show_examples();
            Ok(())
        }

        #[cfg(feature = "secret-fun")]
        Commands::Secret { the_secret } => {
            check_easter_egg(&the_secret);
            Ok(())
        }
    };

    if let Err(e) = result {
        show_abort_message(e);
        return;
    }

    if !cli.unattended {
        read_from_stdin();
    }

    std::process::exit(0);
}

/// Attempt to decode to a string, with optional versioning and fallback.
fn handle_decode_with_optional_version(
    ref_image: &str,
    encoded_image: &str,
    password: String,
    no_files: bool,
    verbose: bool,
    version: Option<Version>,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
    m_cost: Option<u32>,
) -> Result<()> {
    match version {
        Some(ver) => {
            let mut codec = create_codec(&ver);
            apply_decode_settings(&mut codec, no_files, verbose, t_cost, p_cost, m_cost);
            let decoded = codec
                .decode(ref_image, password, encoded_image)
                .map_err(|e| Error::Decoding(format!("Failed to decode with {ver:?}: {e}")))?;
            print_decoded_text(&decoded);
            Ok(())
        }
        None => {
            for ver in &[Version::V3, Version::V2] {
                let mut codec = create_codec(ver);
                apply_decode_settings(&mut codec, no_files, verbose, t_cost, p_cost, m_cost);
                if let Ok(decoded) = codec.decode(ref_image, password.clone(), encoded_image) {
                    print_decoded_text(&decoded);
                    return Ok(());
                }
            }
            Err(Error::Decoding(
                "Failed to decode with all available versions.".to_string(),
            ))
        }
    }
}

/// Attempt to decode to a file, with optional versioning and fallback.
fn handle_decode_file_with_optional_version(
    ref_image: &str,
    encoded_image: &str,
    output_file: &str,
    password: String,
    no_files: bool,
    verbose: bool,
    version: Option<Version>,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
    m_cost: Option<u32>,
) -> Result<()> {
    match version {
        Some(ver) => {
            let mut codec = create_codec(&ver);
            apply_decode_settings(&mut codec, no_files, verbose, t_cost, p_cost, m_cost);
            codec
                .decode_file(ref_image, password, encoded_image, output_file)
                .map_err(|e| Error::Decoding(format!("Failed to decode file with {ver:?}: {e}")))?;
            println!("File successfully decoded to {output_file}");
            Ok(())
        }
        None => {
            for ver in &[Version::V3, Version::V2] {
                let mut codec = create_codec(ver);
                apply_decode_settings(&mut codec, no_files, verbose, t_cost, p_cost, m_cost);
                if codec
                    .decode_file(ref_image, password.clone(), encoded_image, output_file)
                    .is_ok()
                {
                    println!("File successfully decoded to {output_file}");
                    return Ok(());
                }
            }
            Err(Error::Decoding(
                "Failed to decode file with all available versions.".to_string(),
            ))
        }
    }
}

/// Handle text encode command.
fn handle_encode(
    ref_image: &str,
    output_image: &str,
    text: &str,
    password: String,
    codec: &mut Box<dyn Codec>,
) -> Result<()> {
    match codec.encode(ref_image, password, text, output_image) {
        Ok(_) => {
            println!("The text has been successfully encoded.");
            Ok(())
        }
        Err(e) => Err(Error::Encoding(e.to_string())),
    }
}

/// Handle file encode command.
fn handle_encode_file(
    ref_image: &str,
    output_image: &str,
    input_file: &str,
    password: String,
    codec: &mut Box<dyn Codec>,
) -> Result<()> {
    match codec.encode_file(ref_image, password, input_file, output_image) {
        Ok(_) => {
            println!("The file has been successfully encoded.");
            Ok(())
        }
        Err(e) => Err(Error::Encoding(e.to_string())),
    }
}

/// Create a codec instance based on the specified version.
fn create_codec(version: &Version) -> Box<dyn Codec> {
    match version {
        Version::V2 => Box::new(StegaV2::new("PsiStega3")) as Box<dyn Codec>,
        Version::V3 => Box::new(StegaV3::new()) as Box<dyn Codec>,
    }
}

/// Check for version-specific feature compatibility and warn the user.
fn check_version_compatibility(version: &Version, locker: bool, read_once: bool) {
    match version {
        Version::V2 => {}
        Version::V3 => {
            if locker || read_once {
                eprintln!("WARNING: --locker and --read-once are only supported in v2. These flags will be ignored.");
            }
        }
    }
}

/// Apply codec settings for encoding operations.
fn apply_encode_settings(
    codec: &mut Box<dyn Codec>,
    version: &Version,
    locker: bool,
    no_noise: bool,
    no_files: bool,
    read_once: bool,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
    m_cost: Option<u32>,
    verbose: bool,
    unattended: bool,
) {
    // locker and read_once may only be specified with v2.
    if matches!(version, Version::V2) {
        if locker {
            let mut enabled = true;
            if !unattended {
                print!("WARNING: the file locker will render the encoded data unrecoverable if 5 or more attempts to decode the data are unsuccessful. ");
                enabled = read_confirm_from_stdin(CONFIRM_PROMPT);
            }
            codec.set_flag_state(ConfigFlags::Locker, enabled);
        }
        if read_once {
            let mut enabled = true;
            if !unattended {
                print!("WARNING: the file locker will render the encoded data unrecoverable after it has been successfully decoded once. ");
                enabled = read_confirm_from_stdin(CONFIRM_PROMPT);
            }
            codec.set_flag_state(ConfigFlags::ReadOnce, enabled);
        }
    }

    // Argon2 parameters may only be specified with versions v2 and v3.
    if matches!(version, Version::V2 | Version::V3) {
        if let Some(t) = t_cost {
            codec.set_parameter(ConfigParams::TCost(t));
        }
        if let Some(p) = p_cost {
            codec.set_parameter(ConfigParams::PCost(p));
        }
        if let Some(m) = m_cost {
            codec.set_parameter(ConfigParams::MCost(m));
        }
    }

    if no_noise {
        codec.set_flag_state(ConfigFlags::NoiseLayer, false);
    }
    if no_files {
        codec.set_flag_state(ConfigFlags::OutputFiles, false);
    }
    if verbose {
        codec.set_flag_state(ConfigFlags::Verbose, true);
    }
}

/// Apply codec settings for decoding operations.
fn apply_decode_settings(
    codec: &mut Box<dyn Codec>,
    no_files: bool,
    verbose: bool,
    t_cost: Option<u32>,
    p_cost: Option<u32>,
    m_cost: Option<u32>,
) {
    if no_files {
        codec.set_flag_state(ConfigFlags::OutputFiles, false);
    }
    if verbose {
        codec.set_flag_state(ConfigFlags::Verbose, true);
    }

    // Apply Argon2 parameters if provided.
    if let Some(t) = t_cost {
        codec.set_parameter(ConfigParams::TCost(t));
    }
    if let Some(p) = p_cost {
        codec.set_parameter(ConfigParams::PCost(p));
    }
    if let Some(m) = m_cost {
        codec.set_parameter(ConfigParams::MCost(m));
    }
}

/// Print decoded text with handling for binary data.
fn print_decoded_text(plaintext: &str) {
    println!("{}", "-".repeat(32));
    if plaintext.contains('�') {
        println!("One or more unprintable characters were detected in the decoded data. This could mean the data is binary data and cannot be printed here.");
        println!("Please try decoding the data using the decode-file command instead.");
    } else {
        println!("{plaintext}");
    }
}

/// Get password with verification (for encoding).
fn get_password_with_verify(password_arg: Option<String>, unattended: bool) -> Result<String> {
    if let Some(pwd) = password_arg {
        return Ok(pwd);
    }
    if unattended {
        return Ok(String::new());
    }
    let pwd_1 = get_password("Password: ");
    let pwd_2 = get_password("Confirm password: ");
    if pwd_1 == pwd_2 {
        Ok(pwd_1.unwrap_or_default())
    } else {
        Err(Error::PasswordMismatch)
    }
}

/// Prompt the user to input a password.
fn get_password(prompt: &str) -> Option<String> {
    println!("{prompt}");
    rpassword::read_password().ok()
}

/// Read a line of text from stdin.
fn read_from_stdin() -> String {
    let mut input_string = String::new();
    stdin()
        .read_line(&mut input_string)
        .expect("Failed to read a line.");
    input_string
}

/// Read a yes/no confirmation from stdin.
fn read_confirm_from_stdin(prompt: &str) -> bool {
    println!("{prompt}");
    let confirm = read_from_stdin().trim().to_lowercase();
    confirm == "y" || confirm == "yes"
}

/// Display an error message.
pub fn show_abort_message(error: Error) {
    eprintln!("Error: {error}");
    std::process::exit(1);
}

/// Check for the easter egg passphrase.
#[cfg(feature = "secret-fun")]
fn check_easter_egg(text: &str) {
    let mut hasher = Sha3_512::new();
    hasher.update(text.to_lowercase().as_bytes());
    let hash_bytes = hasher.finalize();
    let decoded = decode(&EASTER_EGG_ENCODED, &hash_bytes);
    if let Ok(s) = String::from_utf8(decoded) {
        rainbow_centered(&s);
    } else {
        eprintln!("That was not the correct secret, sorry... 😢");
    }
}

/// Encode a message with a stateful rolling hash.
#[cfg(feature = "secret-fun")]
#[allow(dead_code)]
fn encode(msg: &[u8], hash_bytes: &[u8]) -> Vec<u8> {
    let mut state: u8 = 0xAD;

    msg.iter()
        .enumerate()
        .map(|(i, &b)| {
            let h = hash_bytes[(i + state as usize * 3) % hash_bytes.len()];
            let t = b ^ h.rotate_left((state & 3) as u32) ^ (i as u8).wrapping_mul(31);

            state = state.wrapping_add(t ^ h).rotate_left(2);
            t
        })
        .collect()
}

/// Decode a message with a stateful rolling hash.
#[cfg(feature = "secret-fun")]
fn decode(encoded: &[u8], hash_bytes: &[u8]) -> Vec<u8> {
    let mut state: u8 = 0xAD;

    encoded
        .iter()
        .enumerate()
        .map(|(i, &t)| {
            let h = hash_bytes[(i + state as usize * 3) % hash_bytes.len()];
            let b = t ^ h.rotate_left((state & 3) as u32) ^ (i as u8).wrapping_mul(31);

            state = state.wrapping_add(t ^ h).rotate_left(2);
            b
        })
        .collect()
}

/// Print a string in a smooth rainbow gradient centered in the terminal.
#[cfg(feature = "secret-fun")]
fn rainbow_centered(text: &str) {
    let (width, _) = size().unwrap_or((80, 0));
    let text_len = text.chars().count() as u16;
    let padding = if width > text_len {
        (width - text_len) / 2
    } else {
        0
    };

    print!("{}", " ".repeat(padding as usize));

    for (i, c) in text.chars().enumerate() {
        let rgb = rainbow_color(i as f32 / text_len as f32);
        print!("\x1b[38;2;{};{};{}m{}", rgb.0, rgb.1, rgb.2, c);
    }

    println!("\x1b[0m");
}

/// Generate a smooth rainbow color from 0.0 to 1.0.
#[cfg(feature = "secret-fun")]
fn rainbow_color(pos: f32) -> (u8, u8, u8) {
    let pi = std::f32::consts::PI;
    let two_pi = 2.0 * pi;

    let r = (pos * two_pi).sin() * 0.5 + 0.5;
    let g = (pos * two_pi + 2.0 * pi / 3.0).sin() * 0.5 + 0.5;
    let b = (pos * two_pi + 4.0 * pi / 3.0).sin() * 0.5 + 0.5;

    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// Show the example command line arguments.
fn show_examples() {
    let split = "-".repeat(60);
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    println!("\n{split}");
    println!("{}ENCODING EXAMPLES{}", bold, reset);
    println!("{split}");

    println!("{}Encode text into an image (v3 - default):{}", bold, reset);
    println!("  psistega3 encode reference.png encoded.png \"A very important message.\"");
    println!("  (You will be prompted for a password)\n");

    println!(
        "{}Encode text with password provided (not recommended):{}",
        bold, reset
    );
    println!("  psistega3 encode reference.png encoded.png \"Secret message\" -p password\n");

    println!("{}Encode using v2 codec:{}", bold, reset);
    println!("  psistega3 encode reference.png encoded.png \"Secret\" --version v2\n");

    println!("{}Encode a file:{}", bold, reset);
    println!("  psistega3 encode-file reference.png encoded.png input.txt\n");

    println!(
        "{}Encode with file locker enabled (v2 only):{}",
        bold, reset
    );
    println!("  psistega3 encode reference.png encoded.png \"Secret\" --version v2 --locker\n");

    println!("{split}");
    println!("{}DECODING EXAMPLES{}", bold, reset);
    println!("{split}");

    println!("{}Decode text from an image:{}", bold, reset);
    println!("  psistega3 decode reference.png encoded.png");
    println!("  (Automatically tries v3, then v2 if v3 fails)\n");

    println!(
        "{}Decode with password provided (not recommended):{}",
        bold, reset
    );
    println!("  psistega3 decode reference.png encoded.png -p password\n");

    println!(
        "{}Decode with custom Argon2 parameters (v3):{}",
        bold, reset
    );
    println!("  psistega3 decode reference.png encoded.png -p password --t-cost 8 --p-cost 8 --m-cost 65536\n");

    println!("{}Decode a file:{}", bold, reset);
    println!("  psistega3 decode-file reference.png encoded.png output.txt\n");

    println!("{split}");
    println!("{}ADVANCED OPTIONS{}", bold, reset);
    println!("{split}");

    println!(
        "{}Disable noise layer (faster, less secure):{}",
        bold, reset
    );
    println!("  psistega3 encode reference.png output.png \"Text\" --no-noise\n");

    println!("{}Enable read-once protection (v2 only):{}", bold, reset);
    println!("  psistega3 encode reference.png output.png \"Text\" --version v2 --read-once\n");

    println!(
        "{}Custom Argon2 parameters for stronger encryption (v3 only):{}",
        bold, reset
    );
    println!(
        "  psistega3 encode ref.png out.png \"Secret\" --t-cost 4 --p-cost 4 --m-cost 65536\n"
    );

    println!("{}Unattended mode (no prompts):{}", bold, reset);
    println!("  psistega3 --unattended encode ref.png out.png \"Text\" -p password\n");

    println!("{split}");
    println!("{}ARGON2 TUNING (v2 and v3){}", bold, reset);
    println!("{split}");

    println!("The Argon2 parameters control the key derivation function:");
    println!("  --t-cost  : Time cost (iterations). Higher = slower but more secure.");
    println!(
        "  --m-cost  : Memory cost (KiB). Higher = more memory used, more resistant to attacks."
    );
    println!("  --p-cost  : Parallelism (threads). Number of threads to use.");
    println!("IMPORTANT: When decoding, you must provide the identical Argon2 parameters used during encoding.\n");

    println!("Example encode with high security:");
    println!("  psistega3 encode ref.png out.png \"Top Secret\" --t-cost 10 --p-cost 10 --m-cost 131072\n");

    println!("Example decode with matching parameters:");
    println!("  psistega3 decode ref.png out.png --t-cost 10 --p-cost 10 --m-cost 131072\n");

    println!("{split}");
    println!("{}NOTES{}", bold, reset);
    println!("{split}");

    println!("When decoding, if the data isn't valid Unicode, an error will be returned.\n");
    println!("This {}usually{} means the decoded data is binary rather than text. Using a file output (e.g., via `decode-file`) is recommended.", bold, reset);
}
