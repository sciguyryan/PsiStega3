use crate::error::{Error, Result};

use image::{ColorType, DynamicImage, GenericImage, GenericImageView, ImageError, ImageFormat};

#[derive(Clone, Debug)]
pub struct ImageWrapper {
    /// The `DynamicImage` instance that is wrapped.
    img: DynamicImage,
    /// A boolean indicating whether modifications to the image should be permitted.
    read_only: bool,
    /// The format of the image.
    format: ImageFormat,
}

impl ImageWrapper {
    pub fn new() -> Self {
        Self {
            img: DynamicImage::new_bgra8(1, 1),
            read_only: false,
            format: ImageFormat::Png,
        }
    }

    pub fn foo(&self) -> Vec<u8> {
        self.img.to_bytes()
    }

    #[allow(dead_code)]
    pub fn benfords_law(&self) -> [u32; 10] {
        let mut law = [0; 10];
        for (_, _, pixel) in self.img.pixels() {
            let val = pixel[0] as u16 + pixel[1] as u16 + pixel[2] as u16 + pixel[3] as u16;
            let digit = (val % 10) as usize;
            law[digit] += 1;
        }

        law
    }

    /// Return the image's dimension.
    pub fn dimensions(&self) -> (u32, u32) {
        self.img.dimensions()
    }

    /// Returns a specified number of contiguous pixels, originating from a [`Point`] object.
    /// This is from the top left of the image.
    #[allow(dead_code)]
    pub fn get_contiguous_pixel_by_coord(&self, coord: Point, count: u16) -> Vec<image::Rgba<u8>> {
        let (w, _) = self.img.dimensions();
        let start = (coord.y * w + coord.x - 1) as usize;
        self.img
            .pixels()
            .skip(start)
            .take(count as usize)
            .map(|(_, _, img)| img)
            .collect()
    }

    /// Get the format of the image.
    pub fn get_image_format(&self) -> ImageFormat {
        self.format
    }

    /// Return the value of a pixel at (x, y).
    /// This is from the top left of the image.
    pub fn get_pixel(&self, x: u32, y: u32) -> image::Rgba<u8> {
        self.img.get_pixel(x, y)
    }

    /// Return the value of a pixel using a [`Point`] object.
    /// This is from the top left of the image.
    pub fn get_pixel_by_coord(&self, coord: Point) -> image::Rgba<u8> {
        self.img.get_pixel(coord.x, coord.y)
    }

    /// Calculate the total number of pixels available in the reference image.
    pub fn get_total_pixels(&self) -> u64 {
        let (w, h) = self.img.dimensions();
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
                // Convert the internal image into the correct colour type.
                // This enforced that the output images are the correct type.
                // TODO: should we simply convert everything that isn't
                // TODO: RBGA16 into RGBA8 here instead?
                let i = match img.color() {
                    ColorType::Rgb8 | ColorType::Rgba8 => {
                        let rbga = img.into_rgba8();
                        DynamicImage::ImageRgba8(rbga)
                    }
                    ColorType::Rgb16 | ColorType::Rgba16 => {
                        let rbga = img.into_rgba16();
                        DynamicImage::ImageRgba16(rbga)
                    }
                    _ => {
                        // We currently do not handle any of the other format types.
                        return Err(Error::ImageTypeInvalid);
                    }
                };

                let mut w = ImageWrapper {
                    img: i,
                    read_only: false,
                    format: ImageFormat::Png,
                };

                // If we can't identify the image format then we can't work
                // with this file format.
                if let Ok(f) = ImageFormat::from_path(file_path) {
                    w.format = f;
                } else {
                    return Err(Error::ImageTypeInvalid);
                }

                // TODO: remove this stuff.
                let pineapple = w.foo();
                log::debug!("{:?}", pineapple);

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

    /// Calculate the coordinates of a pixel from the pixel index.
    ///
    /// # Arguments
    ///
    /// * `pixel` - The index of the pixel within the image.
    ///
    pub fn pixel_coordinate(&self, pixel: u32) -> Point {
        let w = self.img.dimensions().0;

        // Note: strictly speaking we don't need to subtract the modulo
        // when calculating 'y' as we are performing an integer division.
        // I have none the less done this for the sake of safety and clarity.
        let x = pixel % w;
        let y = (pixel - x) / w;

        Point::new(x, y)
    }

    /// Set the value of the the pixel at (x, y).
    /// This is from the top left of the image.
    pub fn put_pixel(&mut self, x: u32, y: u32, pixel: image::Rgba<u8>) -> bool {
        if !self.read_only {
            self.img.put_pixel(x, y, pixel);
        }

        self.read_only
    }

    /// Set the value of the the pixel using a [`Point`] object.
    /// This is from the top left of the image.
    pub fn put_pixel_by_coord(&mut self, coord: Point, pixel: image::Rgba<u8>) -> bool {
        self.put_pixel(coord.x, coord.y, pixel)
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

        // TODO: at present the output file type will depend on the
        // TODO: output path file extension.
        // TODO: Should this be restricted to being the same as the
        // TODO: input format?
        self.img.save(path)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Point {
    pub x: u32,
    pub y: u32,
}

impl Point {
    fn new(x: u32, y: u32) -> Self {
        Self { x, y }
    }
}
