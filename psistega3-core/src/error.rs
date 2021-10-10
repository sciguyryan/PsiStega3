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
            Error::Argon2InvalidParams => "one or more invalid parameters passed to argon2 hasher",
            Error::Argon2NoHash => "error creating an Argon2 hash with the specified parameters",
            Error::Base64Decoding => "the base64 string was invalid and could not be decoded.",
            Error::DataTooLarge => "the data is too large",
            Error::DecryptionFailed => "the data could not be decrypted; the data was invalid.",
            Error::EncryptionFailed => "the data could not be encrypted",
            Error::File => "a generic file-related error occurred.",
            Error::FileCreate => "an error occurred when attempting to create a file.",
            Error::FileHashingError => "an error occurred when attempting to hash a file.",
            Error::FileRead => "an error occurred when attempting to read from a file.",
            Error::FileWrite => "an error occurred when attempting to write to a file.",
            Error::ImageDimensionsInvalid => {
                "invalid image dimensions: the total number of pixels must be divisible by two"
            }
            Error::ImageDimensionsMismatch => "the dimensions of the image files are not equal",
            Error::ImageInsufficientSpace => {
                "there is insufficient space to encode the data within the image"
            }
            Error::ImageOpening => "error when attempting to load the specified image",
            Error::ImageSaving => "error when attempting to save the specified image",
            Error::ImageTypeInvalid => "invalid image pixel type",
            Error::PathInvalid => "the specified path is invalid or does not exist",
            Error::VersionInvalid => "invalid version number",
        })
    }
}

impl std::error::Error for Error {}
