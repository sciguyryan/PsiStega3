use core::fmt;

/// Result with internal [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid image dimensions.
    ImageDimensionsInvalid,
    /// Generic image loading error (will need to be made more granular).
    ImageLoading,
    /// Invalid version number.
    VersionInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::ImageDimensionsInvalid => "invalid image dimensions: the total number of pixels must be divisible by two",
            Error::ImageLoading => "unable to load the specified image file",
            Error::VersionInvalid => "invalid version number",
        })
    }
}

impl std::error::Error for Error {}