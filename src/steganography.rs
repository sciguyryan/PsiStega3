
use crate::error::{Error, Result};
use crate::hashers::*;
use crate::version::Version;

use image::{DynamicImage, GenericImageView};
use std::convert::TryFrom;

pub const V1_ARGON_T_COST: u32 = 6;
pub const V1_ARGON_P_COST: u32 = 3;
pub const V1_ARGON_M_COST: u32 = 4096;
pub const V1_ARGON_VERSION: argon2::Version = argon2::Version::V0x13;

#[derive(Debug)]
pub struct Steganography {
    pub images: [DynamicImage; 2],
}

impl Default for Steganography {
    fn default() -> Self {
        Self::new()
    }
}

impl Steganography {
    pub fn new() -> Self {
       Self {
            // Create a dummy image for the two potential input images.
            // These will be replaced with the relevant method calls.
            images: [image::DynamicImage::new_bgr8(1, 1), image::DynamicImage::new_bgr8(1, 1)]
        }
    }

    /// Encrypt the plaintext and write the resulting data into an image file.
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
    pub fn encode(&mut self, version: u32, input_path: &str, key: &str, plaintext: &str, output_path: &str) -> Result<()> {
        log::debug!("Loading (reference) image file @ {}", &input_path);

        let v = match Version::try_from(version) {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Invalid encoder version specified: {:?}", version);
                return Err(e);
            }
        };

        match Steganography::load_image(input_path) {
            Ok(img) => {
                self.images[0] = img;
            },
            Err(e) => {
                log::debug!("Error loading reference image file: {:?}", e);
               return Err(e);
            }
        }

        log::debug!("Successfully loaded reference image file!");
        log::debug!("Using encoder version: {:?}", &v);

        // Replace the placeholder image with a container image for the output image.
        let (w, h) =  self.images[0].dimensions();
        image::DynamicImage::new_rgba16(w, h);

        // Call the encoding function for the specified version.
        match v {
            Version::V0x01 => self.encode_v1(),
        }
    }

    fn encode_v1(&mut self) -> Result<()> {
        Ok(())
    }

    /// Read and decrypt the data from an image file.
    ///
    /// # Arguments
    ///
    /// * `version` - The version of the encoding algorithm to use.
    /// * `original_path` - The original image file path.
    /// * `key` - The plaintext encryption key to be used.
    /// * `encoded_path` - The encoded image file path.
    ///
    /// Note: When using this method the first image in the `images` array will be the reference image and the second will be the encoded image.
    pub fn decode(&mut self, version: u32, original_path: &str, key: &str, encoded_path: &str) -> Result<&str> {
        log::debug!("Loading (reference) image file @ {}", &original_path);

        let v = match Version::try_from(version) {
            Ok(v) => v,
            Err(e) => {
                log::debug!("Invalid decoder version specified: {:?}", version);
                return Err(e);
            }
        };

        match Steganography::load_image(original_path) {
            Ok(img) => {
                self.images[0] = img;
            },
            Err(e) => {
                log::debug!("Error loading reference image file: {:?}", e);
               return Err(e)
            }
        }

        log::debug!("Successfully loaded reference image file!");
        log::debug!("Using decoder version: {:?}", &v);

         // Call the encoding function for the specified version.
        match v {
            Version::V0x01 => self.decode_v1(),
        }
    }

    fn decode_v1(&mut self) -> Result<&str> {
        Ok("")
    }

    /// Attempt to load an image from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the image file.
    ///
    fn load_image(file_path: &str) -> Result<DynamicImage> {
        let img = match image::open(file_path) {
            Ok(img) => {
                // The image was successfully loaded.
                // Now we need to validate if the file can be used.
                match Steganography::validate_image(&img) {
                    Ok(_) => {
                        img
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            },
            // TODO: add more granularity to the errors here.
            Err(_) => {
                return Err(Error::ImageLoading);
            }
        };

        let rgba = img.into_rgba16();

        Ok(DynamicImage::ImageRgba16(rgba))
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
    }

    /// Calculate the total number of pixels available in the reference image.
    pub fn get_total_pixels(&self) -> u32 {
        let (w, h) =  self.images[0].dimensions();
        w * h
    }

    /// Calculate the total number of cells available in the reference image.
    pub fn get_total_cells(&self) -> u32 {
        // Each cell is 2x1 pixels in size.
        self.get_total_pixels() / 2
    }
}