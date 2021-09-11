use crate::error::Result;
use crate::image_wrapper::ImageWrapper;

pub trait Codec {
    fn encode(&mut self, input_path: &str, key: &str, plaintext: &str, output_path: &str) -> Result<()>;
    fn decode(&mut self) ->  Result<&str>;

    fn load_image(file_path: &str) -> Result<ImageWrapper>;
    fn validate_image(image: &ImageWrapper) -> Result<()>;
}
