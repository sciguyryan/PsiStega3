use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Insufficient number of arguments to perform the specified action.
    InsufficientArguments,
    /// The supplied version number was invalid.
    InvalidVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InsufficientArguments => {
                "Insufficient arguments were provided to complete the specified action."
            }
            Error::InvalidVersion => "No valid version was supplied for the encoder/decoder.",
        })
    }
}

impl std::error::Error for Error {}
