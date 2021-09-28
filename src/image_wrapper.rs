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
}

impl ImageWrapper {
    pub fn new() -> Self {
        Self {
            image_bytes: Vec::with_capacity(1),
            read_only: false,
            format: ImageFormat::Png,
            dimensions: (1, 1),
        }
    }

    #[allow(dead_code)]
    pub fn benfords_law(&self) -> [u32; 10] {
        let mut pixel = 0;
        let mut law = [0; 10];
        loop {
            let p: Vec<&u8> = self.image_bytes.iter().skip(pixel * 4).take(4).collect();
            if p.len() < 4 {
                break;
            }

            // This is actually safe as we are ensuring that there will
            // always be at least 4 entries in the vector above.
            unsafe {
                let val = **p.get_unchecked(0) as u16
                    + **p.get_unchecked(1) as u16
                    + **p.get_unchecked(2) as u16
                    + **p.get_unchecked(3) as u16;
                let digit = (val % 10) as usize;
                law[digit] += 1;
            }

            pixel += 1;
        }

        law
    }

    /// Return the image's dimension.
    pub fn dimensions(&self) -> (u32, u32) {
        self.dimensions
    }

    /// Returns a vector containing references to the bytes that
    /// represent the channels of the pixels that fall within the
    /// specified index range.
    pub fn get_contiguous_pixel_by_index(&self, pixel: usize, count: u16) -> Vec<&u8> {
        let start = pixel * 4;
        let channels = count as usize * 4;
        let v: Vec<&u8> = self.image_bytes.iter().skip(start).take(channels).collect();

        assert!(v.len() == channels);

        v
    }

    /// Returns a vector containing mutable references to the bytes that
    /// represent the channels of the pixels that fall within the
    /// specified index range.
    pub fn get_contiguous_pixel_by_index_mut(&mut self, pixel: usize, count: u16) -> Vec<&mut u8> {
        assert!(!self.read_only);

        let start = pixel * 4;
        let channels = count as usize * 4;
        let v: Vec<&mut u8> = self
            .image_bytes
            .iter_mut()
            .skip(start)
            .take(channels)
            .collect();

        assert!(v.len() == channels);

        v
    }

    /// Get the format of the image.
    pub fn get_image_format(&self) -> ImageFormat {
        self.format
    }

    /// Returns a vector containing references to the bytes that
    /// represent the channels of the pixel at the specified index.
    pub fn get_pixel(&self, pixel: usize) -> Vec<&u8> {
        let start = pixel * 4;
        let v: Vec<&u8> = self.image_bytes.iter().skip(start).take(4).collect();

        // This should never happen as all images are transmuted
        // into the RGBA8 format... but just in case.
        assert!(v.len() == 4);

        v
    }

    /// Returns a vector containing mutable references to the bytes that
    /// represent the channels of the pixel at the specified index.
    pub fn get_pixel_mut(&mut self, pixel: usize) -> Vec<&mut u8> {
        assert!(!self.read_only);

        let start = pixel * 4;
        let v: Vec<&mut u8> = self.image_bytes.iter_mut().skip(start).take(4).collect();

        // This should never happen as all images are transmuted
        // into the RGBA8 format... but just in case.
        assert!(v.len() == 4);

        v
    }

    /// Calculate the total number of pixels available in the reference image.
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
        match image::open(file_path) {
            Ok(img) => {
                let image = DynamicImage::ImageRgba8(img.into_rgba8());

                // For simplicity, we convert everything into the
                // RGBA8 format.
                let mut w = ImageWrapper {
                    image_bytes: image.to_bytes(),
                    read_only: false,
                    format: ImageFormat::Png,
                    dimensions: image.dimensions(),
                };

                // If we can't identify the image format then we can't work
                // with this file format.
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
    /// Note: the file type is derived from the file extension.
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
