use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView};

#[derive(Clone)]
pub struct ImageWrapper {
    img: DynamicImage
}

impl ImageWrapper {
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
                    img
                };
                Ok(wrapper)
            },
            // TODO: add more granularity to the errors here.
            Err(_) => {
                Err(Error::ImageOpening)
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

    pub fn color(&self) -> image::ColorType {
        self.img.color()
    }

    pub fn dimensions(&self) -> (u32, u32) {
        self.img.dimensions()
    }

    pub fn get_pixel(&self, x: u32, y: u32) -> image::Rgba<u8> {
        self.img.get_pixel(x, y)
    }

    pub fn put_pixel(&mut self, x: u32, y: u32, pixel: image::Rgba<u8>) {
        self.img.put_pixel(x, y, pixel);
    }

    pub fn save(&self, path: &str) -> image::ImageResult<()> {
        self.img.save(path)
    }
}
