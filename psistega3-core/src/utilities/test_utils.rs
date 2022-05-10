use path_absolutize::Absolutize;
use rand::Rng;
use std::{fs, path::PathBuf};



const FILE_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-__";

pub(crate) struct TestUtils {
    /// The base folder path for the test files.
    test_base_path: PathBuf,
    /// A vector of files that will be automatically cleared when the instance is dropped.
    auto_clear_files: Vec<String>,
}

impl TestUtils {
    pub fn new(sub_path: &[&str]) -> Self {
        Self {
            test_base_path: TestUtils::test_base_path(sub_path),
            auto_clear_files: Vec::new(),
        }
    }

    /// Add a file to the automatic file clearing list.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file to be cleared.
    ///
    fn add_auto_clear_file(&mut self, path: &str) {
        self.auto_clear_files.push(path.to_string());
    }

    /// Get a test file and copy it to a random output path.
    ///
    /// # Arguments
    ///
    /// * `file` - The name of the original test file, including the extension.
    /// * `ext` - The extension of the copy file.
    /// * `auto_clear` - Whether this file should be automatically cleared after the test has finished.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn copy_in_file_to_random_out(
        &mut self,
        file: &str,
        ext: &str,
        auto_clear: bool,
    ) -> String {
        let old_path = self.get_in_file(file);
        let new_path = self.get_out_file(ext, auto_clear);

        let r = fs::copy(&old_path, &new_path);
        assert!(r.is_ok(), "failed to create copy of file");

        new_path
    }

    /// Generate a random ASCII string of a specified length.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the final string.
    ///
    pub fn generate_ascii_string(len: usize) -> String {
        let mut str = String::new();

        let chars_len = FILE_CHARS.len();

        for _ in 0..len {
            let index = rand::thread_rng().gen_range(0..chars_len);
            let char = FILE_CHARS.chars().nth(index).unwrap();
            str.push(char);
        }

        str
    }

    /// Get the path to the current execution directory.
    fn get_current_dir() -> PathBuf {
        std::env::current_dir().unwrap()
    }

    /// Get the full path to a random output file path.
    /// These files are created in the operating system's temp directory.
    ///
    /// # Arguments
    ///
    /// * `ext` - The extension of the temporary file.
    /// * `auto_clear` - Whether this file should be automatically cleared after the test has finished.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn get_out_file(&mut self, ext: &str, auto_clear: bool) -> String {
        let random: u128 = rand::thread_rng().gen();

        let mut path = std::env::temp_dir();
        path.push(format!("{}.{}", random, ext));

        let path = path.absolutize().unwrap();
        let path_str = path.to_str().unwrap().to_string();

        // Do we need to automatically delete this file after we are finished?
        if auto_clear {
            self.add_auto_clear_file(&path_str);
        }

        path_str
    }

    /// Get the full path to a test file.
    ///
    /// # Arguments
    ///
    /// * `file` - The name of the test file, including the extension.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn get_in_file(&self, file: &str) -> String {
        let mut path = self.test_base_path.clone();
        path.push(file);

        assert!(path.exists(), "unable to find test file.");

        let path = path.absolutize().unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Get the full path to a test file.
    ///
    /// # Arguments
    ///
    /// * `file` - The name of the test file, including the extension.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn get_in_file_no_verify(&self, file: &str) -> String {
        let mut path = self.test_base_path.clone();
        path.push(file);

        let path = path.absolutize().unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Compute the base path to the tests directory.
    ///
    /// # Arguments
    ///
    /// * `sub_paths` - A slice of string slices representing the path to the tests.
    ///
    fn test_base_path(sub_paths: &[&str]) -> PathBuf {
        let mut path = TestUtils::get_current_dir();

        // These will always be the same.
        path.push("..");
        path.push("tests");
        path.push("assets");

        // Push any additional sub-paths.
        for p in sub_paths {
            path.push(p);
        }

        assert!(path.exists(), "testing file directory does not exist.");

        path
    }
}

impl Drop for TestUtils {
    fn drop(&mut self) {
        for f in &self.auto_clear_files {
            let _ = fs::remove_file(f);
        }
    }
}
