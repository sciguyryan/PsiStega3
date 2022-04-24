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
    /// Unable to get the file metadata.
    FileMetadata,
    /// Insufficient number of arguments to perform the specified action.
    InsufficientArguments,
    /// The supplied version number was invalid
    InvalidVersion,
    /// Unable to create the data file.
    LockerFileCreation,
    /// Unable to determine the data file path.
    LockerFilePath,
    /// Unable to read the data file.
    LockerFileRead,
    /// Unable to write the data file.
    LockerFileWrite,
    /// The supplied passwords did not match.
    PasswordMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Decoding(s) => s,
            Error::Encoding(s) => s,
            Error::FileMetadata => "Unable to get the file metadata.",
            Error::InsufficientArguments => {
                "Insufficient arguments were provided to complete the specified action."
            }
            Error::InvalidVersion => "No valid version was supplied for the encoder/decoder.",
            Error::LockerFileCreation => "Unable to create the locker file.",
            Error::LockerFilePath => "Unable to find the locker file path.",
            Error::LockerFileRead => "Unable to read the locker file.",
            Error::LockerFileWrite => "Unable to write the locker file.",
            Error::PasswordMismatch => {
                "The entered passwords did not match. Please check and try again."
            }
        })
    }
}

impl std::error::Error for Error {}
