
use crate::version::Version;
use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView};
use log::debug;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Steganography {
    version: Version,
    pub images: [DynamicImage; 2],
}

impl Steganography {
    pub fn new() -> Self{
        let mut v = Self {
            version: Version::default(),

            // Create a dummy image for the two potential input images.
            // These will be replaced with the relevant method calls.
            images: [image::DynamicImage::new_bgr8(1, 1), image::DynamicImage::new_bgr8(1, 1)]
        };

        v
    }

    /// Write the input data into an image.
    ///
    /// # Arguments
    ///
    /// * `version` - The version of the encoding algorithm to use.
    /// * `input_path` - The input image file path.
    /// * `key` - The plaintext encryption key to be used.
    /// * `plaintext` - The plaintext to be encrypted and encoded into the image.
    /// * `output_path` - The output image file path.
    ///
    /// Note: When using this method the first image in the `images` array will be the reference image and the second will be the output image.
    fn encode(&mut self, version: u32, input_path: &str, key: &str, plaintext: &str, output_path: &str) -> Result<()> {
        if let Err(e) = self.set_version(version) {
            return Err(e);
        }

        log::debug!("Loading (reference) image file @ {}", &input_path);
        match Steganography::load_image(input_path) {
            Ok(img) => {
                self.images[0] = img;
            },
            Err(e) => {
               return Err(e)
            }
        }

        Ok(())
    }

    fn load_image(file_path: &str) -> Result<DynamicImage> {
        match image::open(file_path) {
            Ok(img) => {
                // The image was successfully loaded.
                // Now we need to validate if the file can be used.
                match Steganography::validate_image(&img) {
                    Ok(_) => {
                        Ok(img)
                    },
                    Err(e) => {
                        Err(e)
                    }
                }
            },
            // TODO: add more granularity to the errors here.
            Err(_) => {
                Err(Error::ImageLoading)
            }
        }
    }

    fn set_version(&mut self, version: u32) -> Result<()> {
        match Version::try_from(version) {
            Ok(r) => {
                self.version = r;
                Ok(())
            },
            Err(e) => Err(e)
        }
    }

    /// Validate if the image can be used with our steganography algorithms.
    ///
    /// # Arguments
    ///
    /// * `image` - A reference to a [`DynamicImage`] object.
    ///
    fn validate_image(image: &DynamicImage) -> Result<()> {
        let (w, h) =  image.dimensions();

        log::debug!("Image dimensions: ({},{})", w, h);

        let pixels = w * h;
        if pixels % 2 == 0 {
            Ok(())
        } else {
            Err(Error::ImageDimensionsInvalid)
        }

        // TODO: validate that the image has RGBA.
    }

    /// Calculate the total number of pixels available in the reference image.
    pub fn total_pixels(&self) -> u32 {
        let (w, h) =  self.images[0].dimensions();
        w * h
    }

    /// Calculate the total number of cells available in the reference image.
    pub fn total_cells(&self) -> u32 {
        // Each cell is 2x1 pixels in size.
        self.total_pixels() / 2
    }
}