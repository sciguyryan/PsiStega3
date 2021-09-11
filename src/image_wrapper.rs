use image::{DynamicImage, GenericImageView};

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ImageWrapper {
    pub img: DynamicImage
}

impl ImageWrapper {
    pub fn new() -> Self {
        Self {
             img: image::DynamicImage::new_bgr8(1, 1)
         }
     }

    /// Attempt to load an image from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    ///
    pub fn load_image(&mut self, file_path: &str) -> Result<()> {
        match image::open(file_path) {
            Ok(img) => {
                self.img = img;
                Ok(())
            },
            // TODO: add more granularity to the errors here.
            Err(_) => {
                Err(Error::ImageLoading)
            }
        }
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
    pub fn pixel_coordinate(&self, pixel: usize) -> (usize, usize) {
        let w =  self.img.dimensions().0 as usize;

        // Note: strictly speaking we don't need to subtract the modulo
        // when calculating 'y' as we are performing an integer division.
        // I have none the less done this for the sake of safety and clarity.
        let x = pixel % w;
        let y = pixel - x / w;

        (x, y)
    }
}

impl Default for ImageWrapper {
    fn default() -> Self {
        Self::new()
    }
}
