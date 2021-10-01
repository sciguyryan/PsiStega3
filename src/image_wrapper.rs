use crate::error::{Error, Result};

use image::{DynamicImage, GenericImageView, ImageError, ImageFormat};

#[derive(Clone, Debug)]
pub struct ImageWrapper {
    /// The `DynamicImage` instance that is wrapped.
    //img: DynamicImage,
    image_bytes: Vec<u8>,
    /// A boolean indicating whether modifications to the image should be permitted.
    read_only: bool,
    /// The format of the image.
    format: ImageFormat,
    /// The dimensions of the original image.
    dimensions: (u32, u32),
    /// The underlying pixel data type of the image.
    image_type: ImageColourSpace,
}

impl ImageWrapper {
    pub fn new() -> Self {
        Self {
            image_bytes: Vec::with_capacity(1),
            read_only: false,
            format: ImageFormat::Png,
            dimensions: (1, 1),
            image_type: ImageColourSpace::Bgr(8),
        }
    }

    #[allow(dead_code)]
    pub fn benfords_law(&self) -> [u32; 10] {
        let mut pixel = 0;
        let mut law = [0; 10];
        loop {
            let start = pixel * 4;
            let end = start + 4;
            let p = &self.image_bytes[start..end];
            if p.len() < 4 {
                break;
            }

            let val = p[0] as u16 + p[1] as u16 + p[2] as u16 + p[3] as u16;
            let digit = (val % 10) as usize;
            law[digit] += 1;

            pixel += 1;
        }

        law
    }

    /// Return the image's dimension.
    pub fn dimensions(&self) -> (u32, u32) {
        self.dimensions
    }

    /// Get a reference slice to the channel data for a specified range of pixels.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the first pixel of data to be returned.
    /// * `count` - The number of pixels of data to be returned.
    ///
    #[allow(dead_code)]
    pub fn get_contiguous_pixel_by_index(&self, pixel: usize, count: u16) -> &[u8] {
        let start = pixel * 4;
        let end = start + (count * 4) as usize;

        let slice = &self.image_bytes[start..end];
        assert!(slice.len() == count as usize * 4);

        slice
    }

    /// Get a mutable reference slice to the channel data for a specified range of pixels.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the first pixel of data to be returned.
    /// * `count` - The number of pixels of data to be returned.
    ///
    pub fn get_contiguous_pixel_by_index_mut(&mut self, pixel: usize, count: u16) -> &mut [u8] {
        let start = pixel * 4;
        let end = start + (count as usize * 4);

        let slice = &mut self.image_bytes[start..end];
        assert!(slice.len() == count as usize * 4);

        slice
    }

    /// Get the format of the image.
    pub fn get_image_format(&self) -> ImageFormat {
        self.format
    }

    /// Get a reference slice to the channel data for a specified pixel.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the pixel to be returned.
    ///
    #[allow(dead_code)]
    pub fn get_pixel(&self, pixel: usize) -> &[u8] {
        let start = pixel * 4;
        let end = start + 4;

        let slice = &self.image_bytes[start..end];
        assert!(slice.len() == 4);

        slice
    }

    /// Get a mutable reference slice to the channel data for a specified pixel.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the pixel to be returned.
    ///
    #[allow(dead_code)]
    pub fn get_pixel_mut(&mut self, pixel: usize) -> &mut [u8] {
        let start = pixel * 4;
        let end = start + 4;

        let slice = &mut self.image_bytes[start..end];
        assert!(slice.len() == 4);

        slice
    }

    /// Calculate the total number of pixels available in the image.
    pub fn get_total_pixels(&self) -> u64 {
        let (w, h) = self.dimensions;
        w as u64 * h as u64
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

        match image::open(file_path) {
            Ok(img) => {
                let image_type = match &img {
                    ImageLuma8(_) => ImageColourSpace::Luma(8),
                    ImageLumaA8(_) => ImageColourSpace::LumaA(8),
                    ImageRgb8(_) => ImageColourSpace::Rgb(8),
                    ImageRgba8(_) => ImageColourSpace::RgbA(8),
                    ImageBgr8(_) => ImageColourSpace::Bgr(8),
                    ImageBgra8(_) => ImageColourSpace::BgrA(8),
                    ImageLuma16(_) => ImageColourSpace::Luma(16),
                    ImageLumaA16(_) => ImageColourSpace::LumaA(16),
                    ImageRgb16(_) => ImageColourSpace::Rgb(16),
                    ImageRgba16(_) => ImageColourSpace::RgbA(16),
                };

                // For simplicity, we convert everything into the
                // RGBA8 format.
                let image = ImageRgba8(img.into_rgba8());

                let mut w = ImageWrapper {
                    image_bytes: image.to_bytes(),
                    read_only: false,
                    format: ImageFormat::Png,
                    dimensions: image.dimensions(),
                    image_type,
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
            // TODO: add more granularity to the errors here.
            Err(_) => Err(Error::ImageOpening),
        }
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
        image::save_buffer_with_format(
            path,
            self.image_bytes.as_slice(),
            w,
            h,
            image::ColorType::Rgba8,
            self.format,
        )
    }
}

#[derive(Clone, Debug)]
pub enum ImageColourSpace {
    /// Luma colour-space images.
    Luma(u8),
    /// Luma colour-space images, with alpha channel.
    LumaA(u8),
    /// Red, green, blue colour-space images.
    Rgb(u8),
    /// Red, green, blue colour-space images, with an alpha channel.
    RgbA(u8),
    // Blue, green, red colour-space images.
    Bgr(u8),
        // Blue, green, red colour-space images, with an alpha channel.
    BgrA(u8),
}
