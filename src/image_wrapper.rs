use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView, ImageError};

#[derive(Clone, Debug)]
pub struct ImageWrapper {
    /// The `DynamicImage` instance that is wrapped.
    img: DynamicImage,
    /// A boolean indicating whether modifications to the image should be permitted.
    read_only: bool
}

impl ImageWrapper {
    pub fn new() -> Self {
        Self {
            img: DynamicImage::new_bgra8(1, 1),
            read_only: false
        }
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
                let wrapper = ImageWrapper {
                    img,
                    read_only: false
                };
                Ok(wrapper)
            },
            // TODO: add more granularity to the errors here.
            Err(_) => {
                Err(Error::ImageOpening)
            }
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

    /// Calculate the total number of pixels available in the reference image.
    pub fn get_total_pixels(&self) -> u64 {
        let (w, h) =  self.img.dimensions();
        w as u64 * h as u64
    }

    /// Calculate the coordinates of a pixel from the pixel index.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the pixel within the image.
    ///
    pub fn pixel_coordinate(&self, pixel: u32) -> Point {
        let w =  self.img.dimensions().0;

        // Note: strictly speaking we don't need to subtract the modulo
        // when calculating 'y' as we are performing an integer division.
        // I have none the less done this for the sake of safety and clarity.
        let x = pixel % w;
        let y = (pixel - x) / w;

        Point::new(x, y)
    }

    /// Return the image's colour type.
    pub fn color(&self) -> image::ColorType {
        self.img.color()
    }

    /// Return the image's dimension.
    pub fn dimensions(&self) -> (u32, u32) {
        self.img.dimensions()
    }

    /// Return the value of the pixel at (x, y). This is from the top left of the image.
    pub fn get_pixel(&self, x: u32, y: u32) -> image::Rgba<u8> {
        self.img.get_pixel(x, y)
    }

    /// Set the value of the the pixel at (x, y). This is from the top left of the image.
    pub fn put_pixel(&mut self, x: u32, y: u32, pixel: image::Rgba<u8>) -> bool {
        if !self.read_only {
            self.img.put_pixel(x, y, pixel);
        }

        self.read_only
    }

    /// Save the buffer to a file at the specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to which the file should be saved.
    ///
    /// Note: the file type is derived from the file extension.
    pub fn save(&self, path: &str) -> image::ImageResult<()> {
        if !self.read_only {
            self.img.save(path)
        } else {
            Err(ImageError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "attempted to write to a read-only file")))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Point {
    pub x: u32,
    pub y: u32,
}

impl Point {
    fn new(x: u32, y: u32) -> Self {
        Self {
            x, y
        }
    }
}
