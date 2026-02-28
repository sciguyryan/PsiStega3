use hashbrown::HashMap;
use rand::seq::SliceRandom;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    error::*,
    utilities::{file_utils, png_utils},
};

/// This struct holds the file locker attempts for the application.
#[derive(Debug)]
pub(crate) struct Locker {
    /// The name of the application.
    application_name: String,
    /// A list of locker entries that are held by the application.
    entries: HashMap<Vec<u8>, u8>,
    /// The postfix to apply to the end of the locker data file.
    file_name_postfix: String,

    /// Attempt to clear the locker file upon exit.
    #[cfg(test)]
    pub clear_on_exit: bool,
}

impl Locker {
    /// The size of an individual locker entry, in bytes.
    const ENTRY_SIZE: usize = 65;

    /// The value at which the XOR cipher will start.
    const XOR_START: u8 = 170;

    pub fn new(application_name: &str, file_name_postfix: &str) -> Result<Self> {
        let mut l = Self {
            application_name: application_name.to_string(),
            entries: HashMap::new(),
            file_name_postfix: file_name_postfix.to_string(),

            #[cfg(test)]
            clear_on_exit: false,
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
    /// * `hash` - The hash of the file.
    ///
    pub fn clear_file_lock(&mut self, hash: &Vec<u8>) {
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
        let locker_dir = self.get_locker_directory();

        // Attempt to create the path to the directory, if it doesn't already exist.
        if fs::create_dir_all(locker_dir).is_err() {
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
    /// * `hash` - The hash of the file.
    ///
    fn force_clear_file_lock(&mut self, hash: &Vec<u8>) {
        self.entries.remove(hash);
    }

    /// Attempt to get a reference to a locker entry by the file's hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the file.
    ///
    #[allow(unused)]
    pub fn get_entry_by_hash(&self, hash: &Vec<u8>) -> Option<&u8> {
        self.entries.get(hash)
    }

    /// Get the directory in which the locker data file should be held.
    ///
    fn get_locker_directory(&self) -> PathBuf {
        /*
          The locker base directory will found in the data directory
            (or temp directory for tests).
          The locker files will be found in a subdirectory containing
            the name of the application, unless running via tests.
        */
        if cfg!(test) {
            std::env::temp_dir()
        } else {
            let mut p = dirs::data_dir().unwrap();
            p.push(&self.application_name);
            p
        }
    }

    /// Get the full path to the locker data file.
    ///
    fn get_locker_file_path(&self) -> Result<String> {
        let mut path = self.get_locker_directory();

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

    /// Increment the attempts for a given file hash, will lock the file if there have been sufficient attempts.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `hash` - The hash of the file.
    ///
    pub fn increment_attempts(&mut self, path: &str, hash: &Vec<u8>) {
        // We need to update the locker entry, or add it if it
        // doesn't already exist.

        if let Some(attempts) = self.entries.get_mut(hash) {
            // The entry exists within the entries list.
            // We need to update the attempts counter.
            *attempts += 1;
        } else {
            // The entry does not exists within the entries list.
            // We need to add it with the default attempt value.
            self.entries.insert(hash.clone(), 0);
        }

        // Do we need to lock the file?
        if self.is_file_locked(hash) {
            // The entry exists within the list, has reached the attempts limit
            //   but hasn't been locked.
            // We need to attempt to lock the file.
            // If successful then it can be removed from the list.
            if self.lock_file(path) {
                self.force_clear_file_lock(hash);
            }
        }
    }

    /// Check whether a given file's hash has received 5 or more unsuccessful attempts to decrypt the file.
    ///
    pub fn is_file_locked(&self, hash: &Vec<u8>) -> bool {
        /*
          A file is considered locked if 5 or more attempts have been made
            to decode it, where the decryption was unsuccessful, meaning instances
            where an invalid key had been used.

          Note that the entry is added to the entry list upon the first
            unsuccessful attempt, which means that the 0th attempt is actually
            the 1st attempt. Programmer logic!
        */
        if let Some(attempts) = self.entries.get(hash) {
            *attempts >= 4
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
        //   the entry should be removed from the list.
        // It isn't possible to lock a directory.
        if Path::new(path).is_dir() {
            return true;
        }

        let mut is_read_only = false;

        // If the file is read-only, then we need to unset that flag.
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
        //   encoded data or not.
        let Ok(mut img) = ImageWrapper::load_from_file(path, false) else {
            return false;
        };

        // Scramble the image.
        img.scramble();

        // If the file was successfully scrambled then it can be removed from
        // the entry list, otherwise we will need to try again later.
        let res = img.save_lossless(path);

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
        for (i, (hash, attempts)) in self.entries.iter().enumerate() {
            eprintln!("Entry {i} : {hash:?} = {attempts}");
        }
    }

    /// Attempt to read the entries within the locker data file.
    ///
    fn read_locker_file(&mut self) -> Result<()> {
        let path = self.get_locker_file_path()?;
        if !file_utils::path_exists(&path) {
            return Ok(());
        }

        // This will indicate a corrupted locker file.
        let meta = file_utils::get_file_metadata(&path)?;
        if meta.len() % (Locker::ENTRY_SIZE as u64) != 0 {
            return Err(Error::LockerFileRead);
        }

        // The file will automatically be closed when it goes out of scope.
        let Ok(mut file) = File::open(path) else {
            return Err(Error::LockerFileRead);
        };

        // This will hold the chunk of data that is being read.
        let mut buffer = [0u8; Locker::ENTRY_SIZE];

        // Loop until we have read the entire file (in chunks).
        let mut xor = Locker::XOR_START;
        while let Ok(n) = file.read(&mut buffer) {
            // Either there are not enough bytes to create a file access struct instance.
            if n < Locker::ENTRY_SIZE {
                break;
            }

            // Decipher the bytes.
            Locker::cipher_slice(&mut buffer, xor);

            // Construct the entry based on the read bytes.
            let last = Locker::ENTRY_SIZE - 1;
            self.entries.insert(buffer[..last].to_vec(), buffer[last]);

            xor -= 1;
        }

        Ok(())
    }

    /// Directly update the attempts for a given file hash.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the image file.
    /// * `hash` - The hash of the file to be unlocked.
    ///
    pub(crate) fn set_attempts(&mut self, path: &str, hash: &Vec<u8>, attempts: u8) {
        // We need to update the locke entry, or add it if it
        // doesn't already exist.
        if let Some(att) = self.entries.get_mut(hash) {
            // The entry exists within the entries list.
            // We need to update the counter.
            *att = attempts;
        } else {
            // The entry does not exists within the entries list.
            // We need to add it to the list.
            self.entries.insert(hash.clone(), attempts);
        }

        // Do we need to lock the file?
        if self.is_file_locked(hash) {
            // The entry exists within the list, has hit the attempt limited
            // but hasn't been locked. We need to attempt to lock the file.
            // If successful then it can be removed from the list.
            if self.lock_file(path) {
                self.force_clear_file_lock(hash);
            }
        }
    }

    /// Attempt to write the held locker entries into the locker data file.
    ///
    fn write_locker_file(&mut self) -> Result<()> {
        let mut file = self.create_locker_file()?;

        // Shuffle the vector, just for kicks.
        let mut entries_vec: Vec<(Vec<u8>, u8)> =
            self.entries.iter().map(|e| (e.0.clone(), *e.1)).collect();
        let mut rng = rand::rng();
        entries_vec.shuffle(&mut rng);

        // Iterate over the entries in the attempts list.
        let mut xor = Locker::XOR_START;
        for (hash, attempts) in &self.entries {
            let mut vec = hash.clone();
            vec.push(*attempts);

            // Cipher the bytes.
            Locker::cipher_slice(&mut vec, xor);

            // If we hit an error then stop writing the file immediately.
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
        #[cfg(test)]
        {
            // If we are running a test, most of the time we will want to clear
            // the locker data file upon exit.
            if self.clear_on_exit {
                let Ok(locker_path) = self.get_locker_file_path() else {
                    return;
                };

                if file_utils::path_exists(&locker_path) {
                    // We will ignore any errors here as there is nothing
                    // that can be done to delete the file.
                    _ = fs::remove_file(&locker_path);
                }
                return;
            }
        }

        // If the file is read-only then we need to unset that
        // option, otherwise we will be unable to write to the file.
        let Ok(locker_path) = self.get_locker_file_path() else {
            return;
        };
        let Ok(state) = file_utils::get_file_read_only_state(&locker_path) else {
            return;
        };
        if state {
            let _ = file_utils::toggle_file_read_only_state(&locker_path);
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
        let _ = file_utils::toggle_file_read_only_state(&locker_path);
    }
}

#[cfg(test)]
mod tests_locker {
    use crate::{
        hashers,
        utilities::{file_utils, png_utils, test_utils::*},
    };

    use super::Locker;

    /// The default entry for use when hashing.
    const HASH_STR: &str = "ElPsyKongroo";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["locker"];

    /// Create a file locker instance, or panic if it fails.
    ///
    /// `Note:` we will attempt to clear the locker file upon exit by default.
    ///
    fn create_locker_instance_or_assert(file_name_postfix: &str) -> Locker {
        let mut l = Locker::new("PsiStega3-Tests", file_name_postfix)
            .expect("could not initialize locker instance");
        l.clear_on_exit = true;
        l
    }

    #[test]
    fn test_is_file_locked() {
        let hash = hashers::sha3_512_string(HASH_STR).to_vec();
        let locker_pf = TestUtils::generate_ascii_string(16);

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // No locker entry for the hash should exist.
        assert!(
            !locker.is_file_locked(&hash),
            "locker entry exists, without it being added."
        );

        locker.entries.insert(hash.clone(), 3);

        // A locker entry for the hash should exist, but there are not enough attempts for the entry to be locked.
        assert!(
            !locker.is_file_locked(&hash),
            "entry is marked as locked, despite there being insufficient attempts"
        );

        // This attempt value should be the threshold for entry to be locked.
        let entry = locker.entries.get_mut(&hash).unwrap();
        *entry = 4;
        assert!(
            locker.is_file_locked(&hash),
            "entry is not marked as locked, despite there being sufficient attempts"
        );
    }

    #[test]
    fn test_read_write_locker_file() {
        let hash = hashers::sha3_512_string(HASH_STR).to_vec();
        let locker_pf = TestUtils::generate_ascii_string(16);

        // The locker instance should save the entries when goes out of scope.
        {
            let mut locker = create_locker_instance_or_assert(&locker_pf);
            locker.clear_on_exit = false;
            locker.entries.clear();
            locker.entries.insert(hash.clone(), 3);
        }

        // The new locker instance should read the prior list of entries upon creation.
        let locker = create_locker_instance_or_assert(&locker_pf);

        assert!(
            !locker.entries.is_empty(),
            "incorrect number of locker entries present upon loads"
        );

        // The entry should exist within the data loaded by the file locker instance.
        let entry2 = locker.entries.get(&hash);
        assert!(
            entry2.is_some(),
            "entry was not found upon loading the locker instance"
        );

        // The entry should be identical to the original entry that was added.
        assert_eq!(
            *entry2.unwrap(),
            3,
            "entry was not the same after unloading and reloading"
        );
    }

    #[test]
    fn test_update_access_attempts() {
        let tu = TestUtils::new(&BASE);

        let locker_pf = TestUtils::generate_ascii_string(16);
        let original_path = tu.get_in_file("dummy.png");
        let hash = hashers::sha3_512_file(&original_path)
            .expect("failed to create file hash")
            .to_vec();

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // The file hash should not be in the entries list.
        let entry = locker.entries.get(&hash);
        assert!(
            entry.is_none(),
            "entry was found in the entries list, and should not be"
        );

        locker.increment_attempts(&original_path, &hash);

        // The entry should now be present in the entries list, with a default attempts value of zero.
        let entry = locker.entries.get(&hash);
        assert!(
            entry.is_some(),
            "entry was found in the entries list, and should not be"
        );
        assert_eq!(
            *entry.unwrap(),
            0,
            "entry was found in the entries list, but the attempts field was invalid"
        );

        // Next we need to test of the entry correctly updates.
        locker.increment_attempts(&original_path, &hash);
        let entry = locker.entries.get(&hash);
        assert_eq!(
            *entry.unwrap(),
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

        // Compute the hash of the original file.
        let old_hash = hashers::sha3_512_file(&old_path)
            .expect("failed to create file hash")
            .to_vec();

        let mut locker = create_locker_instance_or_assert(&locker_pf);

        // Add the entry with 4 (0th is the first attempt) attempts. The next failed attempt will lock the file.
        locker.entries.insert(old_hash.clone(), 3);
        locker.increment_attempts(&copy_path, &old_hash);

        // The file hash should have changed.
        let new_hash = hashers::sha3_512_file(&copy_path)
            .expect("failed to create file hash")
            .to_vec();
        assert_ne!(
            new_hash, old_hash,
            "the hash of the copy and original file are the same, no file locking took place"
        );

        // The (old) file hash should no longer be in the entries list.
        let entry = locker.entries.get(&old_hash);
        assert!(
            entry.is_none(),
            "entry was found in the entries list, after it should have been removed"
        );

        // The file should also no longer contain a bKGD chunk.
        let chunk = png_utils::read_chunk_raw(&copy_path, png_utils::PngChunkType::Bkgd);
        assert!(
            chunk.is_none(),
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
    }
}
