use std::{fs::File, io::BufWriter};

use crate::{
    error::{Error, Result},
    utilities::{file_utils, misc_utils, png_utils},
};

use image::{
    codecs::{
        bmp::BmpEncoder, farbfeld::FarbfeldEncoder, png::PngEncoder, tiff::TiffEncoder,
        webp::WebPEncoder,
    },
    DynamicImage::*,
    ExtendedColorType, GenericImageView, ImageEncoder, ImageError, ImageFormat,
};
use rand::RngExt;

#[derive(Clone)]
pub struct ImageWrapper {
    image_bytes: Vec<u8>,
    /// The format of the image.
    format: ImageFormat,
    /// The dimensions of the original image.
    dimensions: (u32, u32),
    /// The underlying pixel colour type of the image.
    colour_type: ExtendedColorType,
    // A boolean indicating whether modifications to the image should be permitted.
    read_only: bool,
}

impl ImageWrapper {
    /// Return the image's dimension.
    #[inline]
    pub fn dimensions(&self) -> (u32, u32) {
        self.dimensions
    }

    /// Get a reference slice for a specified number of subcells of data, starting from a given start index.
    ///
    /// # Arguments
    ///
    /// * `start_index` - The starting index of the subcell to be returned.
    /// * `count` - The number of subcells of data to be returned.
    ///
    /// `Note:` A subcell is the space required to store a nibble of data.
    #[inline(always)]
    pub fn get_subcells_from_index(&self, start_index: usize, count: usize) -> &[u8] {
        let start = start_index * 4;
        let end = start + (count * 4) as usize;
        unsafe { self.image_bytes.get_unchecked(start..end) }
    }

    /// Get a mutable reference slice for a specified number of subcells of data, starting from a given start index.
    ///
    /// # Arguments
    ///
    /// * `start_index` - The starting index of the subcell to be returned.
    /// * `count` - The number of subcells of data to be returned.
    ///
    /// `Note:` A subcell is the space required to store a nibble of data.
    #[inline(always)]
    pub fn get_subcells_from_index_mut(&mut self, start_index: usize, count: usize) -> &mut [u8] {
        let start = start_index * 4;
        let end = start + (count * 4) as usize;
        unsafe { self.image_bytes.get_unchecked_mut(start..end) }
    }

    /// Get the format of the image.
    #[inline(always)]
    pub fn get_image_format(&self) -> ImageFormat {
        self.format
    }

    /// Calculate the total number of channels available in the image.
    #[inline(always)]
    pub fn get_total_channels(&self) -> u64 {
        self.image_bytes.len() as u64
    }

    /// Attempt to load an image from a file.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `read_only` - A boolean indicating whether the image should be loaded in read-only mode.
    pub fn load_from_file(path: &str, read_only: bool) -> Result<ImageWrapper> {
        // We can't load an image that doesn't exist.
        if !file_utils::path_exists(path) {
            return Err(Error::PathInvalid);
        }

        // If we can't identify the image format then we cannot
        // go any further here.
        let format = if let Ok(f) = ImageFormat::from_path(path) {
            f
        } else {
            return Err(Error::ImageTypeInvalid);
        };

        let Ok(image) = image::open(path) else {
            return Err(Error::ImageOpening);
        };

        if matches!(format, ImageFormat::Png)
            && png_utils::find_chunk_start(path, png_utils::PngChunkType::Actl).is_some()
        {
            // If we ever handle these, we'll need to go through each frame and
            // modify each of them separately.
            // For now, we just don't support them at all.
            return Err(Error::AnimatedPngNotSupported);
        }

        let colour_type = match &image {
            ImageLuma8(_) => ExtendedColorType::L8,
            ImageLumaA8(_) => ExtendedColorType::La8,
            ImageLumaA16(_) => ExtendedColorType::La16,
            ImageLuma16(_) => ExtendedColorType::L16,
            ImageRgb8(_) => ExtendedColorType::Rgb8,
            ImageRgba8(_) => ExtendedColorType::Rgba8,
            ImageRgb16(_) => ExtendedColorType::Rgb16,
            ImageRgba16(_) => ExtendedColorType::Rgba16,
            ImageRgb32F(_) => ExtendedColorType::Rgb32F,
            ImageRgba32F(_) => ExtendedColorType::Rgba32F,
            _ => return Err(Error::ImageFormatNotRecognized),
        };

        let dimensions = image.dimensions();
        let image_bytes = image.into_bytes();

        Ok(ImageWrapper {
            image_bytes,
            format,
            dimensions,
            colour_type,
            read_only,
        })
    }

    // Save the underlying image data to a file at the specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to which the file should be saved.
    pub fn save_lossless(&self, path: &str) -> image::ImageResult<()> {
        assert!(!self.read_only, "attempted to write to a read-only file");

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        let (w, h) = self.dimensions;
        let colour = self.colour_type;

        match &self.format {
            ImageFormat::Bmp => {
                let encoder = BmpEncoder::new(&mut writer);
                encoder.write_image(&self.image_bytes, w, h, colour)
            }
            ImageFormat::Farbfeld => {
                let encoder = FarbfeldEncoder::new(writer);
                encoder.write_image(&self.image_bytes, w, h, colour)
            }
            ImageFormat::Png => {
                let encoder = PngEncoder::new(writer);
                encoder.write_image(&self.image_bytes, w, h, colour)
            }
            ImageFormat::Tiff => {
                let encoder = TiffEncoder::new(writer);
                encoder.write_image(&self.image_bytes, w, h, colour)
            }
            ImageFormat::WebP => {
                let encoder = WebPEncoder::new_lossless(writer);
                encoder.write_image(&self.image_bytes, w, h, colour)
            }
            _ => Err(ImageError::Unsupported(
                image::error::UnsupportedError::from_format_and_kind(
                    self.format.into(),
                    image::error::UnsupportedErrorKind::Format(self.format.into()),
                ),
            )),
        }
    }

    /// Scramble the data within the image file.
    pub fn scramble(&mut self) {
        let mut rng = misc_utils::secure_seeded_xoroshiro512();

        // Iterate over each of the image bytes and modify them randomly.
        // The file will be visually the same, but will be modified such that
        // any encoded data is rendered invalid.
        for b in &mut self.image_bytes {
            // If the value is 0 then the new value will always be 1.
            // If the value is 255 then the new value will always be 254.
            // Otherwise the value will be assigned to be ±1.
            if !rng.random_bool(0.5) {
                continue;
            }

            *b = match *b {
                0 => 1,
                1..=254 => {
                    if rng.random_bool(0.5) {
                        *b + 1
                    } else {
                        *b - 1
                    }
                }
                255 => 254,
            };
        }
    }
}
