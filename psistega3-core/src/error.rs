use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// One or more invalid Argon2 parameters specified.
    Argon2InvalidParams,
    /// Unable to create an Argon2 hash with the provided inputs.
    Argon2NoHash,
    /// Unable to decode a base64 string.
    Base64Decoding,
    /// The total amount number of cells exceeds the maximum amount available.
    DataTooLarge,
    /// The data could not be decrypted; the data was invalid.
    DecryptionFailed,
    /// The data could not be encrypted.
    EncryptionFailed,
    /// A generic file-related error.
    File,
    /// Error creating a file.
    FileCreate,
    /// An error occurred while attempting to hash a file.
    FileHashingError,
    /// Error reading from a file.
    FileRead,
    /// Error writing to a file.
    FileWrite,
    /// Invalid image dimensions.
    ImageDimensionsInvalid,
    /// The dimensions of the encoded image are different than those of the reference image.
    ImageDimensionsMismatch,
    /// There is insufficient space within the image to encode the specified data.
    ImageInsufficientSpace,
    /// There was an error when attempting to load an image file.
    ImageOpening,
    /// There was an error when attempting to save an image file.
    ImageSaving,
    /// The image type is cannot be used for steganography.
    ImageTypeInvalid,
    /// The specified path is invalid.
    PathInvalid,
    /// Invalid version number.
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Argon2InvalidParams => "One or more invalid parameters passed to the Argon2 hashing algorithm.",
            Error::Argon2NoHash => "Error creating an Argon2 hash with the specified parameters.",
            Error::Base64Decoding => "The base64 string was invalid and could not be decoded.",
            Error::DataTooLarge => "The data is too large",
            Error::DecryptionFailed => "The data could not be decrypted; the data was invalid.",
            Error::EncryptionFailed => "The data could not be encrypted.",
            Error::File => "A generic file-related error occurred.",
            Error::FileCreate => "An error occurred when attempting to create a file.",
            Error::FileHashingError => "An error occurred when attempting to hash a file.",
            Error::FileRead => "An error occurred when attempting to read from a file.",
            Error::FileWrite => "An error occurred when attempting to write to a file.",
            Error::ImageDimensionsInvalid => {
                "Invalid image dimensions: the total number of available data channels must be divisible by 8."
            }
            Error::ImageDimensionsMismatch => "The dimensions of the image files are not equal.",
            Error::ImageInsufficientSpace => {
                "There is insufficient space to encode the data within the image."
            }
            Error::ImageOpening => "Error when attempting to load the specified image.",
            Error::ImageSaving => "Error when attempting to save the specified image.",
            Error::ImageTypeInvalid => "Invalid image pixel type.",
            Error::PathInvalid => "The specified path is invalid or does not exist.",
            Error::VersionInvalid => "The version number is invalid.",
        })
    }
}

impl std::error::Error for Error {}
