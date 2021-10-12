use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// An error occurred while attempting to decode data from an image.
    Decoding(String),
    /// An error occurred while attempting to encode data into an image.
    Encoding(String),
    /// Insufficient number of arguments to perform the specified action.
    InsufficientArguments,
    /// The supplied version number was invalid.
    InvalidVersion,
    /// No password was supplied.
    NoPassword,
    /// The supplied passwords did not match.
    PasswordMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Decoding(s) => s,
            Error::Encoding(s) => s,
            Error::InsufficientArguments => {
                "Insufficient arguments were provided to complete the specified action."
            }
            Error::InvalidVersion => "No valid version was supplied for the encoder/decoder.",
            Error::NoPassword => "No password was supplied.",
            Error::PasswordMismatch => {
                "The entered passwords did not match. Please check and try again."
            }
        })
    }
}

impl std::error::Error for Error {}
