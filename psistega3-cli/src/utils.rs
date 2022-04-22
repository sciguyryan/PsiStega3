use crate::error::*;

/// Write an [`Error`] message on screen and then abort the program.
///
/// # Arguments
///
/// * `error` - The [`Error`] to be displayed on screen.
///
pub fn show_abort_message(error: Error) {
    println!("Error: {}", error);
    std::process::exit(0);
}
