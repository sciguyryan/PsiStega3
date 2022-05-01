use crate::error::{Error, Result};
use crate::macros::*;

use image::{ColorType, ImageFormat};

#[derive(Clone, Debug)]
pub struct ImageWrapper {
    image_bytes: Vec<u8>,
    /// A boolean indicating whether modifications to the image should be permitted.
    read_only: bool,
    /// The format of the image.
    format: ImageFormat,
    /// The dimensions of the original image.
    dimensions: (u32, u32),
    /// The underlying pixel colour type of the image.
    colour_type: ColorType,
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
    /// `Note:` A subcell is space required to store a nibble of data.
    ///
    #[inline]
    pub fn get_subcells_from_index(&self, start_index: usize, count: u16) -> &[u8] {
        let start = start_index * 4;
        let end = start + (count * 4) as usize;
        &self.image_bytes[start..end]
    }

    /// Get a mutable reference slice for a specified number of subcells of data, starting from a given start index.
    ///
    /// # Arguments
    ///
    /// * `start_index` - The starting index of the subcell to be returned.
    /// * `count` - The number of subcells of data to be returned.
    ///
    /// `Note:` A subcell is space required to store a nibble of data.
    ///
    #[inline]
    pub fn get_subcells_from_index_mut(&mut self, start_index: usize, count: u16) -> &mut [u8] {
        let start = start_index * 4;
        let end = start + (count * 4) as usize;
        &mut self.image_bytes[start..end]
    }

    /// Get the format of the image.
    #[inline]
    pub fn get_image_format(&self) -> ImageFormat {
        self.format
    }

    /// Get a reference slice for a specified subcell of data, starting from a given start index.
    ///
    /// # Arguments
    ///
    /// * `start_index` - The starting index of the subcell to be returned.
    ///
    /// `Note:` A subcell is space required to store a nibble of data.
    ///
    #[allow(dead_code)]
    #[inline]
    pub fn get_subcell(&self, start_index: usize) -> &[u8] {
        let start = start_index * 4;
        let end = start + 4;
        &self.image_bytes[start..end]
    }

    /// Get a mutable reference slice for a specified subcell of data, starting from a given start index.
    ///
    /// # Arguments
    ///
    /// * `start_index` - The starting index of the subcell to be returned.
    ///
    /// `Note:` A subcell is space required to store a nibble of data.
    ///
    #[allow(dead_code)]
    #[inline]
    pub fn get_subcell_mut(&mut self, start_index: usize) -> &mut [u8] {
        let start = start_index * 4;
        let end = start + 4;
        &mut self.image_bytes[start..end]
    }

    /// Calculate the total number of channels available in the image.
    pub fn get_total_channels(&self) -> u64 {
        self.image_bytes.len() as u64
    }

    /// Attempt to load an image from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    ///
    pub fn load_from_file(file_path: &str, read_only: bool) -> Result<ImageWrapper> {
        use image::{DynamicImage::*, GenericImageView};

        let image = unwrap_or_return_err!(image::open(file_path), Error::ImageOpening);

        let colour_type = match &image {
            ImageLuma8(_) => ColorType::L8,
            ImageLumaA8(_) => ColorType::La8,
            ImageLumaA16(_) => ColorType::La16,
            ImageLuma16(_) => ColorType::L16,
            ImageRgb8(_) => ColorType::Rgb8,
            ImageRgba8(_) => ColorType::Rgba8,
            ImageRgb16(_) => ColorType::Rgb16,
            ImageRgba16(_) => ColorType::Rgb16,
            ImageRgb32F(_) => ColorType::Rgb32F,
            ImageRgba32F(_) => ColorType::Rgba32F,
            _ => return Err(Error::ImageFormatUnknown),
        };

        let dimensions = image.dimensions();

        let mut w = ImageWrapper {
            image_bytes: image.into_bytes(),
            read_only,
            format: ImageFormat::Png,
            dimensions,
            colour_type,
        };

        // If we can't identify the image format then we cannot
        // go any further here.
        if let Ok(f) = ImageFormat::from_path(file_path) {
            w.format = f;
        } else {
            return Err(Error::ImageTypeInvalid);
        }

        Ok(w)
    }

    /// Save the buffer to a file at the specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to which the file should be saved.
    ///
    /// `Note:` the file type is derived from the file extension.
    ///
    pub fn save(&self, path: &str) -> image::ImageResult<()> {
        assert!(!self.read_only, "attempted to write to a read-only file");

        let (w, h) = self.dimensions;
        image::save_buffer_with_format(path, &self.image_bytes, w, h, self.colour_type, self.format)
    }

    /// Scramble the data within the image file.
    ///
    pub fn scramble(&mut self) {
        use rand::{thread_rng, Rng};

        // Iterate over each of the image bytes and modify them randomly.
        // The file will be visually the same, but will be modified such that
        // any encoded data is rendered invalid.
        for b in &mut self.image_bytes {
            // If the value is 0 then the new value will always be 1.
            // If the value is 255 then the new value will always be 254.
            // Otherwise the value will be assigned to be ±1.
            *b = match *b {
                0 => 1,
                1..=254 => {
                    // We do not need to calculate this if the value is either
                    // 0 or 255. This will slightly improve performance.
                    if thread_rng().gen_bool(0.5) {
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
