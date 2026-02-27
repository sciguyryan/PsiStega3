use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// One or more invalid Argon2 parameters specified.
    Argon2InvalidParams,
    /// Unable to create an Argon2 hash with the provided inputs.
    Argon2NoHash,
    /// Animated image files are not currently supported.
    AnimatedPngNotSupported,
    /// Unable to decode a base64 string.
    Base64Decoding,
    /// The total amount number of cells exceeds the maximum amount available.
    DataTooLarge,
    /// The decoded string isn't valid.
    DecodeStringInvalid,
    /// The data could not be decrypted; the data was invalid.
    DecryptionFailed,
    /// The data could not be encrypted.
    EncryptionFailed,
    /// Error creating a file.
    FileCreate,
    /// An error occurred while attempting to hash a file.
    FileHashingError,
    /// Error reading or writing a file's metadata.
    FileMetadata,
    /// Error opening a file.
    FileOpen,
    /// Error reading from a file.
    FileRead,
    /// Error truncating a file.
    FileTruncate,
    /// Error writing to a file.
    FileWrite,
    /// Invalid image dimensions.
    ImageDimensionsInvalid,
    /// The dimensions of the encoded image are different than those of the reference image.
    ImageDimensionsMismatch,
    /// The image format is unknown.
    ImageFormatNotRecognized,
    /// There is insufficient space within the image to encode the specified data.
    ImageInsufficientSpace,
    /// The image is malformed.
    ImageMalformed,
    /// There was an error when attempting to load an image file.
    ImageOpening,
    /// There was an error when attempting to save an image file.
    ImageSaving(String),
    /// The image type is cannot be used for steganography.
    ImageTypeInvalid,
    /// Unable to create the locker data file.
    LockerFileCreation,
    /// Unable to determine the locker data file path.
    LockerFilePath,
    /// Unable to read the locker data file.
    LockerFileRead,
    /// Unable to write the locker data file.
    LockerFileWrite,
    /// The specified path is invalid.
    PathInvalid,
    /// Invalid version number.
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Argon2InvalidParams => "One or more Argon2 parameters are invalid.",
            Error::Argon2NoHash => "An error occurred while creating an Argon2 hash.",
            Error::AnimatedPngNotSupported => "Animated image files are not currently supported",
            Error::Base64Decoding => "The base64 string is invalid and could not be decoded.",
            Error::DataTooLarge => "The data is too large.",
            Error::DecodeStringInvalid => "The decoded data isn't valid Unicode.",
            Error::DecryptionFailed => "The data could not be decrypted; the data is invalid.",
            Error::EncryptionFailed => "The data could not be encrypted.",
            Error::FileCreate => "An error occurred when attempting to create a file.",
            Error::FileHashingError => "An error occurred when attempting to hash a file.",
            Error::FileOpen => "An error occurred when attempting open a file.",
            Error::FileMetadata => "An error occurred when attempting to read or write a file's metadata.",
            Error::FileRead => "An error occurred when attempting to read from a file.",
            Error::FileTruncate => "An error occurred when attempting to truncate a file.",
            Error::FileWrite => "An error occurred when attempting to write to a file.",
            Error::ImageDimensionsInvalid => {
                "Invalid image dimensions: the total number of available data channels (length × width × 4) must be divisible by 8."
            }
            Error::ImageDimensionsMismatch => "The dimensions of the images are not equal.",
            Error::ImageFormatNotRecognized => "The image format was not recognized.",
            Error::ImageInsufficientSpace => {
                "There is insufficient space to encode the data within the image."
            }
            Error::ImageMalformed => "The image file is malformed.",
            Error::ImageOpening => "Error when attempting to load the image.",
            Error::ImageSaving(s) => s,
            Error::ImageTypeInvalid => "Invalid image pixel type.",
            Error::LockerFileCreation => "Unable to create the locker file.",
            Error::LockerFilePath => "Unable to find the locker file path.",
            Error::LockerFileRead => "Unable to read the locker file.",
            Error::LockerFileWrite => "Unable to write the locker file.",
            Error::PathInvalid => "The path is invalid or does not exist.",
            Error::VersionInvalid => "The version number is invalid.",
        })
    }
}

impl std::error::Error for Error {}
