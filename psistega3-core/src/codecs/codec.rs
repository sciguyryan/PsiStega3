use crate::error::Result;

pub trait Codec {
    /// Encrypt and encode the information into a target image.
    ///
    /// # Arguments
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when encrypting the information.
    /// * `plaintext` - The data to be encrypted and encoded within the reference image.
    /// * `encoded_img_path` - The path that will be used to store the encoded image.
    ///
    fn encode(
        &mut self,
        original_img_path: &str,
        key: String,
        plaintext: &str,
        encoded_img_path: &str,
    ) -> Result<()>;

    /// Encrypt and encode the file contents and name into a target image.
    ///
    /// # Arguments
    ///
    /// * `original_path` - The path to the reference image.
    /// * `key` - The key to be used when encrypting the information.
    /// * `input_file_path` - The path to the file to be encoded image.
    /// * `encoded_path` - The path that will be used to store the encoded image.
    ///
    fn encode_file(
        &mut self,
        original_img_path: &str,
        key: String,
        input_file_path: &str,
        encoded_img_path: &str,
    ) -> Result<()>;

    /// Decrypt and decode the information from an image.
    ///
    /// # Arguments
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when decrypting the information.
    /// * `encoded_img_path` - The path to the modified image.
    ///
    fn decode(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
    ) -> Result<String>;

    /// Decrypt and decode the an encoded file an image.
    ///
    /// * `original_img_path` - The path to the reference image.
    /// * `key` - The key to be used when decrypting the information.
    /// * `encoded_img_path` - The path to the modified image.
    /// * `output_file_path` - The path to the file to be encoded image.
    ///
    fn decode_file(
        &mut self,
        original_img_path: &str,
        key: String,
        encoded_img_path: &str,
        output_file_path: &str,
    ) -> Result<()>;

    /// Enable or disable a specific setting.
    ///
    /// # Arguments
    ///
    /// * `setting` - The setting to be configured.
    /// * `state` - A boolean indicating whether the option should be enabled or disabled.
    ///
    fn set_setting_state(&mut self, setting: Settings, state: bool);
}

/// A list of settings that are applicable to a codec.
pub enum Settings {
    /// Enable or disable the noise map.
    ///
    /// Applicable to: v1.
    NoiseLayer,
    /// Enable or disable fast variance.
    ///
    /// Applicable to: v1.
    FastVariance,
    /// Enable or disable verbose mode.
    ///
    /// Applicable to: v1.
    Verbose,
    /// Enable or disable the saving of files when encoding or decoding.
    ///
    /// Applicable to: v1.
    OutputFiles,
}
