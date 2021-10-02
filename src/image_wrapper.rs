use crate::error::{Error, Result};

use image::{ColorType, DynamicImage, GenericImageView, ImageError, ImageFormat};

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
    pub fn get_subcells_from_index(&self, start_index: usize, count: u16) -> &[u8] {
        let start = start_index * 4;
        let end = start + (count * 4) as usize;
        let slice = &self.image_bytes[start..end];
        assert!(slice.len() == count as usize * 4);

        slice
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
    pub fn get_subcells_from_index_mut(&mut self, start_index: usize, count: u16) -> &mut [u8] {
        let start = start_index * 4;
        let end = start + (count as usize * 4);
        let slice = &mut self.image_bytes[start..end];
        assert!(slice.len() == count as usize * 4);

        slice
    }

    /// Get the format of the image.
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
    pub fn get_subcell(&self, start_index: usize) -> &[u8] {
        let start = start_index * 4;
        let end = start + 4;
        let slice = &self.image_bytes[start..end];
        assert!(slice.len() == 4);

        slice
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
    pub fn get_subcell_mut(&mut self, start_index: usize) -> &mut [u8] {
        let start = start_index * 4;
        let end = start + 4;
        let slice = &mut self.image_bytes[start..end];
        assert!(slice.len() == 4);

        slice
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
    pub fn load_from_file(file_path: &str) -> Result<ImageWrapper> {
        // Just to make the lines a little shorter.
        use DynamicImage::*;

        let image = match image::open(file_path) {
            Ok(img) => img,
            // TODO: add more granularity to the errors here.
            Err(_) => return Err(Error::ImageOpening),
        };

        let colour_type = match &image {
            ImageLuma8(_) => ColorType::L8,
            ImageLumaA8(_) => ColorType::La8,
            ImageRgb8(_) => ColorType::Rgb8,
            ImageRgba8(_) => ColorType::Rgba8,
            ImageBgr8(_) => ColorType::Bgr8,
            ImageBgra8(_) => ColorType::Bgra8,
            ImageLuma16(_) => ColorType::L16,
            ImageLumaA16(_) => ColorType::La16,
            ImageRgb16(_) => ColorType::Rgb16,
            ImageRgba16(_) => ColorType::Rgb16,
        };

        let dimensions = image.dimensions();

        let mut w = ImageWrapper {
            image_bytes: image.into_bytes(),
            read_only: false,
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

    /// Set the read-only state of the image wrapper.
    ///
    /// # Arguments
    ///
    /// * `state` - The new read-only state of the wrapper.
    ///
    pub fn set_read_only(&mut self, state: bool) {
        self.read_only = state;
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
        if self.read_only {
            return Err(ImageError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "attempted to write to a read-only file",
            )));
        }

        let (w, h) = self.dimensions;
        image::save_buffer_with_format(path, &self.image_bytes, w, h, self.colour_type, self.format)
    }
}
