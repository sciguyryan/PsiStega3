use path_absolutize::Absolutize;
use rand::Rng;
use std::path::PathBuf;

/// This class will be used to automatically delete any
/// files generated with the tests.
pub(crate) struct FileCleaner {
    files: Vec<String>,
}

impl FileCleaner {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    pub fn add(&mut self, path: &str) {
        self.files.push(path.to_string());
    }
}

impl Drop for FileCleaner {
    fn drop(&mut self) {
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}

pub(crate) struct TestUtils {
    test_base_path: PathBuf,
}

impl TestUtils {
    pub fn new(sub_path: &[&str]) -> Self {
        Self {
            test_base_path: TestUtils::test_base_path(sub_path),
        }
    }

    /// Get the path to the current execution directory.
    fn get_current_dir() -> PathBuf {
        std::env::current_dir().unwrap()
    }

    /// Compute the base path to the tests directory.
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

    /// Get the full path to a random output file path, with a given extension.
    /// These files are created in the operating system's temp directory.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn get_out_file(ext: &str) -> String {
        let random: u128 = rand::thread_rng().gen();

        let mut path = std::env::temp_dir();
        path.push(format!("{}.{}", random, ext));

        let path = path.absolutize().unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Get the full path to a test file.
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
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn get_in_file_no_verify(&self, file: &str) -> String {
        let mut path = self.test_base_path.clone();
        path.push(file);

        let path = path.absolutize().unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Get a test file and copy it to a random output path.
    ///
    /// `Note:` This path is normalized to avoid creating any issues
    /// with relative paths.
    ///
    pub fn copy_in_file_to_random_out(&self, file: &str, ext: &str) -> String {
        let old_path = self.get_in_file(file);
        let new_path = TestUtils::get_out_file(ext);

        let r = std::fs::copy(&old_path, &new_path);
        assert!(r.is_ok(), "failed to create copy of file");

        new_path
    }
}
