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
    /// Invalid image dimensions.
    ImageDimensionsInvalid,
    /// The dimensions of the modified image is not the same as that of the reference image.
    ImageDimensionsMismatch,
    /// The image type is cannot be used for steganography.
    ImageTypeInvalid,
    /// Generic image loading error (will need to be made more granular).
    ImageLoading,
    /// Invalid version number.
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Argon2InvalidParams => "one or more invalid parameters passed to argon2 hasher",
            Error::Argon2NoHash => "error creating an Argon2 hash with the specified parameters",
            Error::ImageDimensionsInvalid => "invalid image dimensions: the total number of pixels must be divisible by two",
            Error::ImageDimensionsMismatch => "the dimensions of the modified image are not equal to the original image",
            Error::ImageTypeInvalid => "invalid image pixel type",
            Error::ImageLoading => "unable to load the specified image file",
            Error::VersionInvalid => "invalid version number",
        })
    }
}

impl std::error::Error for Error {}