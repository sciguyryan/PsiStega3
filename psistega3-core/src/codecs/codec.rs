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

    /// Set the name of the application.
    ///
    /// # Arguments
    ///
    /// * `name` - A string containing the name of the application.
    ///
    /// `Note:` this is intended for custom applications that make use of the PsiStega3 crate.
    ///
    fn set_application_name(&mut self, name: String);

    /// Enable or disable a specific configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The [`Config`] option to be configured.
    /// * `state` - A boolean indicating whether the config option should be enabled or disabled.
    ///
    fn set_config_state(&mut self, config: Config, state: bool);
}

/// A list of configuration options that are applicable to a [`Codec`].
pub enum Config {
    /// Enable or disable the noise map.
    ///
    /// Applicable to: v1, v2.
    NoiseLayer,
    /// Enable or disable verbose mode.
    ///
    /// Applicable to: v1, v2.
    Verbose,
    /// Enable or disable the saving of files when encoding or decoding.
    ///
    /// Applicable to: v1, v2.
    OutputFiles,
    /// Enable or disable the file access locking system for this file.
    ///
    /// Applicable to: v1, v2.
    Locker,
    /// Enable or disable the single-read locker system.
    ///
    /// Applicable to: v1, v2.
    ReadOnce,
    /// Enable or disable version checking.
    ///
    /// Applicable to: v2. This is not applicable to v1 as checks are never performed.
    SkipVersionChecks,
}
