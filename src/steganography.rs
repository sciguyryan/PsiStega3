use std::convert::TryFrom;

use crate::version::Version;
use crate::error::{Error, Result};

use image::{DynamicImage, GenericImage, GenericImageView};

struct Steganography {
    version: Version,
    image: DynamicImage
}

impl Steganography {
    fn new(original_file_path: &str, version: u32) -> Result<Self>{
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

    fn load_original_image(&mut self, original_file_path: &str) -> Result<()> {
        Ok(())
    }

    fn set_version(&mut self, version: u32) -> Result<()> {
        match Version::try_from(version) {
            Err(e) => Err(e),
            Ok(r) => {
                self.version = r;
                Ok(())
            }
        }
    }

}