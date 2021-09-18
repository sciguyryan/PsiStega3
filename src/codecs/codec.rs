use crate::error::Result;

pub trait Codec {
    /// Encrypt and encode the information into a target image.
    ///
    /// # Arguments
    ///
    /// * `original_path` - the path to the reference image.
    /// * `key` - the key to be used when encrypting the information.
    /// * `plaintext` - the data to be encrypted and encoded within the reference image.
    /// * `encoded_path` - the path that will be used to store the encoded image.
    fn encode(&mut self, original_path: &str, key: &str, plaintext: &str, encoded_path: &str) -> Result<()>;

    /// Decrypt and decode the information from an image.
    ///
    /// * `original_path` - the path to the reference image.
    /// * `key` - the key to be used when decrypting the information.
    /// * `encoded_path` - the path to the modified image.
    fn decode(&mut self, original_path: &str, key: &str, encoded_path: &str) ->  Result<&str>;
}
