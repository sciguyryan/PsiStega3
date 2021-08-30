
use crate::version::Version;
use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView};
use log::debug;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct Steganography {
    version: Version,
    pub reference_image: DynamicImage,
    pub modified_image: DynamicImage
}

impl Steganography {
    pub fn new(original_file_path: &str, version: u32) -> Result<Self>{
        let mut v = Self {
            version: Version::default(),

            // Create a dummy image for the two potential input images.
            // These will be replaced with the relevant method calls.
            reference_image: image::DynamicImage::new_bgr8(1, 1),
            modified_image: image::DynamicImage::new_bgr8(1, 1),
        };

        // TODO: handle the error results from these functions.
        v.set_version(version);
        v.load_reference_image(original_file_path);
        Ok(v)
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

    fn load_reference_image(&mut self, file_path: &str) -> Result<()> {
        log::debug!("Loading (reference) image file @ {}", &file_path);

        match Steganography::load_image(file_path) {
            Ok(img) => {
                self.reference_image = img;
                Ok(())
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    fn load_modified_image(&mut self, file_path: &str) -> Result<()> {
        debug!("Loading (modified) image file @ {}", &file_path);

        match Steganography::load_image(file_path) {
            Ok(img) => {
                if img.dimensions() == self.reference_image.dimensions() {
                    self.modified_image = img;
                    Ok(())
                } else {
                    Err(Error::ImageDimensionsMismatch)
                }
            },
            Err(e) => {
                Err(e)
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
        let (w, h) =  self.reference_image.dimensions();
        w * h
    }

    /// Calculate the total number of cells available in the reference image.
    pub fn total_cells(&self) -> u32 {
        // Each cell is 2x1 pixels in size.
        self.total_pixels() / 2
    }
}