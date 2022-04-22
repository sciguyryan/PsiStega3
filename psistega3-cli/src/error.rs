use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unable to create the data file.
    DataFileCreation,
    /// Unable to determine the data file path.
    DataFilePath,
    /// Unable to read the data file.
    DataFileRead,
    /// Unable to write the data file.
    DataFileWrite,
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
    /// The supplied passwords did not match.
    PasswordMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::DataFileCreation => "Unable to create the data file.",
            Error::DataFilePath => "Unable to find the data file path.",
            Error::DataFileRead => "Unable to read the data file.",
            Error::DataFileWrite => "Unable to write the data file.",
            Error::Decoding(s) => s,
            Error::Encoding(s) => s,
            Error::FileMetadata => "Unable to get the file metadata.",
            Error::InsufficientArguments => {
                "Insufficient arguments were provided to complete the specified action."
            }
            Error::InvalidVersion => "No valid version was supplied for the encoder/decoder.",
            Error::PasswordMismatch => {
                "The entered passwords did not match. Please check and try again."
            }
        })
    }
}

impl std::error::Error for Error {}
