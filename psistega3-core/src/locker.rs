use crate::{
    error::*,
    macros::*,
    utilities::{file_utils, misc_utils, png_utils},
};

use filetime::FileTime;
use rand::prelude::SliceRandom;
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// This struct holds the file locker attempts for the application.
#[derive(Debug)]
pub(crate) struct Locker {
    /// The name of the application.
    application_name: String,
    /// A list of [`LockerEntries] that are held by the application.
    entries: Vec<LockerEntry>,
    /// The postfix to apply to the end of the locker data file.
    file_name_postfix: String,
}

impl Locker {
    pub fn new(application_name: &str, file_name_postfix: &str) -> Result<Self> {
        let mut l = Self {
            application_name: application_name.to_string(),
            entries: Vec::with_capacity(20),
            file_name_postfix: file_name_postfix.to_string(),
        };

        l.read_locker_file()?;

        Ok(l)
    }

    /// Cipher a u8 slice using a u8 value.
    ///
    /// # Arguments
    ///
    /// * `slice` - The slice to be ciphered.
    /// * `xor` - The u8 value to be used as the cipher.
    ///
    #[cfg(not(debug_assertions))]
    fn cipher_slice(slice: &mut [u8], xor: u8) {
        for b in slice.iter_mut() {
            *b = !(*b ^ xor)
        }
    }

    /// An empty placeholder function for use when debugging.
    ///
    #[cfg(debug_assertions)]
    fn cipher_slice(_: &mut [u8], _: u8) {}

    /// Clear the locker entry for a given file, if it hasn't already been locked.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    pub fn clear_file_lock(&mut self, hash: &[u8]) {
        // If the file has been locked then we can't unlock it.
        if self.is_file_locked(hash) {
            return;
        }

        self.force_clear_file_lock(hash);
    }

    /// Attempt to create the locker file, including all necessary directories.
    ///
    fn create_locker_file(&mut self) -> Result<File> {
        // Get the expected path to the locker file.
        let locker_dir = self.get_locker_directory()?;

        // Attempt to create the path to the directory, if it doesn't already exist.
        if fs::create_dir_all(&locker_dir).is_err() {
            return Err(Error::LockerFileCreation);
        }

        // Get the path to the locker file.
        let path = self.get_locker_file_path()?;

        match File::create(path) {
            Ok(f) => Ok(f),
            Err(_) => Err(Error::LockerFileCreation),
        }
    }

    /// Forcibly clear the locker entry for a given file.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn force_clear_file_lock(&mut self, hash: &[u8]) {
        if let Some(i) = self.get_entry_index_by_hash(hash) {
            // The hash exists within the list so we should remove it.
            self.entries.remove(i);
        }

        // The hash is not in the entry list, we do not need to
        // do anything here.
    }

    /// Attempt to get a locker entry index by the file's hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn get_entry_index_by_hash(&self, hash: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.hash == hash)
    }

    /// Attempt to get a reference to a locker entry by the file's hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn get_entry_by_hash(&self, hash: &[u8]) -> Option<&LockerEntry> {
        self.entries.iter().find(|e| e.hash == hash)
    }

    /// Attempt to get mutable reference to a locker entry by the file's hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file to be unlocked.
    ///
    fn get_entry_by_hash_mut(&mut self, hash: &[u8]) -> Option<&mut LockerEntry> {
        self.entries.iter_mut().find(|e| e.hash == hash)
    }

    /// Get the directory in which the locker data file should be held.
    ///
    fn get_locker_directory(&self) -> Result<PathBuf> {
        /*
          The locker directory will start from the data directory
            (or temp directory for tests).
          The locker files will be found in a subdirectory containing
            the name of the application, if not running tests.
        */
        let path = if cfg!(test) {
            std::env::temp_dir()
        } else {
            let mut p = dirs::data_dir().unwrap();
            p.push(&self.application_name);
            p
        };

        Ok(path)
    }

    /// Get the full path to the locker data file.
    ///
    fn get_locker_file_path(&self) -> Result<String> {
        let mut path = self.get_locker_directory()?;

        let file_name = if !self.file_name_postfix.is_empty() {
            format!("lock-{}.dat", self.file_name_postfix)
        } else {
            "lock.dat".to_string()
        };

        // Push the file name onto the path.
        path.push(file_name);

        if let Some(p) = path.to_str() {
            Ok(p.to_string())
        } else {
            Err(Error::LockerFilePath)
        }
    }

    /// Check whether a given file's hash has received 5 or more unsuccessful attempts to decrypt the file.
    ///
    pub fn is_file_locked(&self, hash: &[u8]) -> bool {
        /*
          A file is considered locked if 5 or more attempts have been made
            to decode it, where the decryption was unsuccessful, meaning instances
            where an invalid key had been used.

          Note that the entry is added to the entry list upon the first
            unsuccessful attempt, which means that the 0th attempt is actually
            the 1st attempt. Programmer logic!
        */
        if let Some(entry) = self.get_entry_by_hash(hash) {
            entry.attempts >= 4
        } else {
            false
        }
    }

    /// Permanently render a file impossible to decrypt, regardless of whether it contained data or not.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    ///
    pub fn lock_file(&mut self, path: &str) -> bool {
        use crate::image_wrapper::ImageWrapper;

        // If the path does not currently exist then we cannot lock it,
        // this means we shouldn't remove it from the list.
        if !file_utils::path_exists(path) {
            return false;
        }

        // This should never happen, but if it does then
        // the entry should be removed from the list.
        // It isn't possible to lock a directory.
        if Path::new(path).is_dir() {
            return true;
        }

        let mut is_read_only = false;

        // If the file is read only, then we need to unset that flag.
        if let Ok(state) = file_utils::get_file_read_only_state(path) {
            if state {
                let _ = file_utils::toggle_file_read_only_state(path);
                is_read_only = true;
            }
        }

        // Get the last modified date from the file's metadata.
        let mtime = file_utils::get_file_last_modified(path);

        // Now we need to ensure that the file can never be decoded.
        // This will happen regardless of whether the image ever contained
        // encoded data or not.
        let mut img = unwrap_or_return_val!(ImageWrapper::load_from_file(path, false), false);

        // Scramble the image.
        img.scramble();

        // If the file was successfully scrambled then it can be removed from
        // the entry list, otherwise we will need to try again later.
        let res = img.save(path);

        // Next, we need to remove the bKGD chunk from the PNG file.
        // This will prevent the file from being decoded.
        _ = png_utils::remove_bkgd_chunk(path);

        // Spoof the file last modification time of the data file to make it
        // appear as though it were never changed.
        if let Ok(time) = mtime {
            let _ = file_utils::set_file_last_modified(path, time);
        }

        // Toggle the read-only state again, if needed.
        if is_read_only {
            let _ = file_utils::toggle_file_read_only_state(path);
        }

        res.is_ok()
    }

    /// Print the entries in the locker list, debug only.
    ///
    #[allow(dead_code)]
    #[cfg(debug_assertions)]
    fn print_locker_list(&self) {
        println!("Total entries: {}", self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            println!("Entry {} : {}", i, e);
        }
    }

    /// Attempt to read the entries within the locker data file.
    ///
    fn read_locker_file(&mut self) -> Result<()> {
        const ENTRY_SIZE: usize = 33;

        let path = self.get_locker_file_path()?;
        if !file_utils::path_exists(&path) {
            return Ok(());
        }

        // This will indicate a corrupted locker file.
        let meta = file_utils::get_file_metadata(&path)?;
        if meta.len() % (ENTRY_SIZE as u64) != 0 {
            return Err(Error::LockerFileRead);
        }

        // The file will automatically be closed when it goes out of scope.
        let mut file = unwrap_or_return_err!(File::open(path), Error::LockerFileRead);

        // This will hold the chunk of data that is being read.
        let mut buffer = [0u8; ENTRY_SIZE];

        // Loop until we have read the entire file (in chunks).
        let mut xor = 170u8;
        while let Ok(n) = file.read(&mut buffer) {
            // Either there are not enough bytes to create a file access struct instance.
            if n < ENTRY_SIZE {
                break;
            }

            // Decipher the bytes.
            Locker::cipher_slice(&mut buffer, xor);

            // Construct the entry based on the read bytes.
            let fa = LockerEntry::new(&buffer[..32], buffer[32]);
            self.entries.push(fa);

            xor -= 1;
        }

        Ok(())
    }

    /// Update the attempts for a given file hash, will lock the file if there have been enough unsuccessful decryption attempts.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `hash` - The hash of the file to be unlocked.
    ///
    pub fn update_file_lock(&mut self, path: &str, hash: &[u8]) {
        // We need to update the locke entry, or add it if it
        // doesn't already exist.
        if let Some(entry) = self.get_entry_by_hash_mut(hash) {
            // The entry exists within the entries list.
            // We need to update the counter.
            (*entry).attempts += 1;
        } else {
            // The entry does not exists within the entries list.
            // We need to add it with the default attempt value of zero.
            self.entries.push(LockerEntry::new(hash, 0));
        }

        // Do we need to lock the file?
        if self.is_file_locked(hash) {
            // The entry exists within the list, has hit the attempt limited
            // but hasn't been locked. We need to attempt to lock the file.
            // If successful then it can be removed from the list.
            if self.lock_file(path) {
                self.force_clear_file_lock(hash);
            } else {
                // TODO: figure out if anything should be done here.
            }
        }
    }

    /// Attempt to write the held locker entries into the locker data file.
    ///
    fn write_locker_file(&mut self) -> Result<()> {
        let mut file = self.create_locker_file()?;

        // Shuffle the vector, just for kicks.
        let mut rng = rand::thread_rng();
        self.entries.shuffle(&mut rng);

        // Iterate over the entries in the attempts list.
        let mut xor = 170u8;
        for entry in &self.entries {
            let mut vec = entry.hash.clone();
            vec.push(entry.attempts);

            // Cipher the bytes.
            Locker::cipher_slice(&mut vec, xor);

            // If we hit an error then we will stop
            // writing the file immediately.
            if file.write(&vec).is_err() {
                return Err(Error::LockerFileWrite);
            }

            xor -= 1;
        }

        Ok(())
    }
}

impl Drop for Locker {
    fn drop(&mut self) {
        // If the file is read-only then we need to unset that
        // option, otherwise we will be prevented from writing to the file.
        let data_path = unwrap_or_return!(self.get_locker_file_path());
        let state = unwrap_or_return!(file_utils::get_file_read_only_state(&data_path));
        if state {
            let _ = file_utils::toggle_file_read_only_state(&data_path);
        }

        // Get the original last modified date of the file.
        let meta = file_utils::get_file_metadata(&data_path);
        let mut mtime: FileTime = FileTime::now();
        if let Ok(m) = &meta {
            mtime = FileTime::from_last_modification_time(m);
        }

        // If writing the locker file failed, exit immediately and
        // delete the locker file.
        if self.write_locker_file().is_err() {
            if let Ok(path) = self.get_locker_file_path() {
                _ = fs::remove_file(path);
            }
            return;
        }

        // The file should be set as read-only again after the writing
        // operation has finished.
        let _ = file_utils::toggle_file_read_only_state(&data_path);

        // Set the file last modification time of the data file.
        if meta.is_ok() {
            let _ = file_utils::set_file_last_modified(&data_path, mtime);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct LockerEntry {
    hash: Vec<u8>,
    attempts: u8,
}

impl LockerEntry {
    pub fn new(hash: &[u8], attempts: u8) -> Self {
        Self {
            hash: hash.to_vec(),
            attempts,
        }
    }
}

impl fmt::Display for LockerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hash: {}, Attempts: {}",
            misc_utils::u8_slice_to_hex(&self.hash, false),
            self.attempts
        )
    }
}

#[cfg(test)]
mod tests_locker {
    use crate::{
        hashers,
        utilities::{
            file_utils,
            png_utils::{self, PngChunkType},
            test_utils::*,
        },
    };

    use super::{Locker, LockerEntry};

    /// The default entry for use when hashing.
    const HASH_STR: &str = "ElPsyKongroo";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["locker"];

    /// Create a file locker instance, or panic if it fails.
    fn create_locker_instance_or_assert(file_name_postfix: &str) -> Locker {
        Locker::new("PsiStega3-Tests", file_name_postfix)
            .expect("could not initialize locker instance")
    }

    #[test]
    fn test_is_file_locked() {
        let hash = hashers::sha3_256_string(HASH_STR);
        let locker_pf = TestUtils::generate_ascii_string(16);

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // No locker entry for the hash should exist.
        assert!(
            !locker.is_file_locked(&hash),
            "locker entry exists, without it being added."
        );

        locker.entries.push(LockerEntry::new(&hash, 3));

        // A locker entry for the hash should exist, but there are not enough attempts for the entry to be locked.
        assert!(
            !locker.is_file_locked(&hash),
            "entry is marked as locked, despite there being insufficient attempts"
        );

        // This attempt value should be the threshold for entry to be locked.
        locker.entries[0].attempts = 4;
        assert!(
            locker.is_file_locked(&hash),
            "entry is not marked as locked, despite there being sufficient attempts"
        );
    }

    #[test]
    fn test_read_write_locker_file() {
        let hash = hashers::sha3_256_string(HASH_STR);
        let locker_pf = TestUtils::generate_ascii_string(16);
        let entry = LockerEntry::new(&hash, 3);

        // The locker instance should save the entries when goes out of scope.
        {
            let mut locker = create_locker_instance_or_assert(&locker_pf);
            locker.entries.clear();
            locker.entries.push(entry.clone());
        }

        // The new locker instance should read the prior list of entries upon creation.
        let locker = create_locker_instance_or_assert(&locker_pf);

        assert!(
            !locker.entries.is_empty(),
            "incorrect number of locker entries present upon loads"
        );

        // The entry should exist within the data loaded by the file locker instance.
        let entry2 = locker.get_entry_by_hash(&hash);
        assert!(
            entry2.is_some(),
            "entry was not found upon loading the locker instance"
        );

        // The entry should be identical to the original entry that was added.
        assert_eq!(
            *entry2.unwrap(),
            entry,
            "entry was not the same after unloading and reloading"
        );
    }

    #[test]
    fn test_update_access_attempts() {
        let tu = TestUtils::new(&BASE);

        let locker_pf = TestUtils::generate_ascii_string(16);
        let original_path = tu.get_in_file("dummy.png");
        let hash = hashers::sha3_256_file(&original_path).expect("failed to create file hash");

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // The file hash should not be in the entries list.
        let entry = locker.get_entry_by_hash(&hash);
        assert!(
            entry.is_none(),
            "entry was found in the entries list, and should not be"
        );

        locker.update_file_lock(&original_path, &hash);

        // The entry should now be present in the entries list, with a default attempts value of zero.
        let entry = locker.get_entry_by_hash(&hash);
        assert!(
            entry.is_some(),
            "entry was found in the entries list, and should not be"
        );
        assert_eq!(
            entry.unwrap().attempts,
            0,
            "entry was found in the entries list, but the attempts field was invalid"
        );

        // Next we need to test of the entry correctly updates.
        locker.update_file_lock(&original_path, &hash);
        let entry = locker.get_entry_by_hash(&hash);
        assert_eq!(
            entry.unwrap().attempts,
            1,
            "entry was found in the entries list, but the attempts field was invalid"
        );
    }

    #[test]
    fn test_file_lock() {
        let mut tu = TestUtils::new(&BASE);

        let locker_pf = TestUtils::generate_ascii_string(16);
        let old_path = tu.get_in_file("dummy.png");
        let copy_path = tu.copy_in_file_to_random_out("dummy.png", "png", true);

        // Set the copy file as read-only.
        file_utils::toggle_file_read_only_state(&copy_path)
            .expect("failed to set the read-only state of the copied file");

        // Get the last modified timestamp of the original file.
        let old_timestamp = file_utils::get_file_last_modified(&old_path)
            .expect("failed to get the timestamp of the original file");

        // Compute the hash of the original file.
        let old_hash = hashers::sha3_256_file(&old_path).expect("failed to create file hash");

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // Add the entry with 4 (0th is the first attempt) attempts. The next failed attempt will lock the file.
        locker.entries.push(LockerEntry::new(&old_hash, 3));
        locker.update_file_lock(&copy_path, &old_hash);

        // The file hash should have changed.
        let new_hash = hashers::sha3_256_file(&copy_path).expect("failed to create file hash");
        assert_ne!(
            new_hash, old_hash,
            "the hash of the copy and original file are the same, no file locking took place"
        );

        // The (old) file hash should no longer be in the entries list.
        let entry = locker.get_entry_by_hash(&old_hash);
        assert!(
            entry.is_none(),
            "entry was found in the entries list, after it should have been removed"
        );

        // The file should also no longer contain a bKGD chunk.
        let kgd_start = png_utils::find_chunk_start(&copy_path, PngChunkType::Bkgd);
        assert!(
            kgd_start.is_none(),
            "a zTXt chunk was found in the locked PNG file, it should have been removed"
        );

        let locked_read_only = file_utils::get_file_read_only_state(&copy_path);
        assert!(
            locked_read_only.is_ok(),
            "failed to read the read-only state of the locked file"
        );
        assert!(
            locked_read_only.unwrap(),
            "the read-only state of the file was not restored after locking"
        );

        // Get the last modified timestamp of the copied file.
        let copy_timestamp = file_utils::get_file_last_modified(&copy_path)
            .expect("Failed to get the timestamp of the original file");

        assert_eq!(
            copy_timestamp, old_timestamp,
            "the timestamp of the copied file is different than that of the original file"
        );
    }
}
