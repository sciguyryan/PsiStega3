use std::convert::TryFrom;

use crate::version::Version;
use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView};

#[derive(Debug)]
pub struct Steganography {
    version: Version,
    image: DynamicImage
}

impl Steganography {
    pub fn new(original_file_path: &str, version: u32) -> Result<Self>{
        let mut v = Self {
            version: Version::default(),
            // Create a dummy image.
            image: image::DynamicImage::new_bgr8(1, 1),
        };

        // TODO: handle the error results from these functions.
        v.set_version(version);
        v.load_original_image(original_file_path);
        Ok(v)
    }

    fn load_original_image(&mut self, file_path: &str) -> Result<()> {
        match image::open(file_path) {
            Ok(r) => {
                self.image = r;
                Ok(())
            },
            // TODO: add more granularity to the errors here.
            Err(_) => Err(Error::ImageLoading)
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

}