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
    /// The total amount number of cells exceeds the maximum.
    DataTooLarge,
    /// Invalid image dimensions.
    ImageDimensionsInvalid,
    /// The dimensions of the encoded image are different than those of the reference image.
    ImageDimensionsMismatch,
    /// There is insufficient space within the image to encode the specified data.
    ImageInsufficientSpace,
    /// There was an error when attempting to load an image file.
    ImageOpening,
    /// Image is too large.
    ImageTooLarge,
    /// Image is too small.
    ImageTooSmall,
    /// The image type is cannot be used for steganography.
    ImageTypeInvalid,
    /// Invalid version number.
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Argon2InvalidParams => "one or more invalid parameters passed to argon2 hasher",
            Error::Argon2NoHash => "error creating an Argon2 hash with the specified parameters",
            Error::DataTooLarge => "the data is too large",
            Error::ImageDimensionsInvalid => {
                "invalid image dimensions: the total number of pixels must be divisible by two"
            }
            Error::ImageDimensionsMismatch => "the dimensions of the image files are not equal",
            Error::ImageInsufficientSpace => {
                "there is insufficient space to encode the data within the image"
            }
            Error::ImageOpening => "error when attempting to load the specified image",
            Error::ImageTooLarge => "the specified image is too large (> 10,000 x 10,000 pixels)",
            Error::ImageTooSmall => {
                "the specified image is too small (must be larger than 30 x 30 pixels)"
            }
            Error::ImageTypeInvalid => "invalid image pixel type",
            Error::VersionInvalid => "invalid version number",
        })
    }
}

impl std::error::Error for Error {}
