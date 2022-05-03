use crate::{error::*, macros::*, utils};

use filetime::FileTime;
use rand::prelude::SliceRandom;
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Debug)]
pub(crate) struct Locker {
    entries: Vec<LockerEntry>,

    #[cfg(test)]
    pub clear_on_exit: bool,
}

impl Locker {
    pub fn new() -> Result<Self> {
        let mut l = Self {
            entries: Vec::with_capacity(20),

            #[cfg(test)]
            clear_on_exit: false,
        };

        l.read_locker_file()?;

        //l.print_locker_list();

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

    pub fn clear_file_lock(&mut self, hash: &[u8]) {
        // If the file has been locked then we can't unlock it.
        if self.is_file_locked(hash) {
            return;
        }

        self.force_clear_file_lock(hash);
    }

    #[allow(dead_code)]
    pub(crate) fn clear_locks(&mut self) {
        // Clear the entries list.
        self.entries.clear();

        // Write the changes to the file.
        _ = self.write_locker_file();
    }

    fn create_locker_file(&mut self) -> Result<File> {
        let path = unwrap_or_return_err!(Locker::get_locker_file_path(), Error::LockerFilePath);

        match File::create(path) {
            Ok(f) => Ok(f),
            Err(_) => Err(Error::LockerFileCreation),
        }
    }

    fn force_clear_file_lock(&mut self, hash: &[u8]) {
        if let Some(i) = self.get_entry_index_by_hash(hash) {
            // The hash exists within the list so we should remove it.
            self.entries.remove(i);
        }

        // The hash is not in the entry list, we do not need to
        // do anything here.
    }

    fn get_binary_path() -> Result<String> {
        let path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return Err(Error::LockerFilePath),
        };

        if let Some(p) = path.to_str() {
            Ok(p.to_string())
        } else {
            Err(Error::LockerFilePath)
        }
    }

    fn get_entry_index_by_hash(&self, hash: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.hash == hash)
    }

    fn get_entry_by_hash(&self, hash: &[u8]) -> Option<&LockerEntry> {
        self.entries.iter().find(|e| e.hash == hash)
    }

    fn get_entry_by_hash_mut(&mut self, hash: &[u8]) -> Option<&mut LockerEntry> {
        self.entries.iter_mut().find(|e| e.hash == hash)
    }

    fn get_locker_file_path() -> Result<String> {
        let bin_path = Locker::get_binary_path()?;

        // Build the path. Disregard the executable file name and append the
        // data file name.
        let mut path = PathBuf::from(bin_path);
        path.pop();
        path.push("lock.dat");

        if let Some(p) = path.to_str() {
            Ok(p.to_string())
        } else {
            Err(Error::LockerFilePath)
        }
    }

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

    pub fn lock_file(&mut self, path: &str) -> bool {
        use crate::image_wrapper::ImageWrapper;

        // If the path does not currently exist then we cannot lock it,
        // this means we shouldn't remove it from the list.
        if !utils::path_exists(path) {
            return false;
        }

        // This should never happen, but if it does then
        // the entry should be removed from the list.
        // It isn't possible to lock a directory.
        if std::path::Path::new(path).is_dir() {
            return true;
        }

        let mut is_read_only = false;

        // If the file is read only, then we need to unset that flag.
        if let Ok(state) = utils::get_file_read_only_state(path) {
            if state {
                let _ = utils::toggle_file_read_only_state(path);
                is_read_only = true;
            }
        }

        // Get the last modified date from the file's metadata.
        let mtime = utils::get_file_last_modified_timestamp(path);

        // Now we need to ensure that the file can never be decoded.
        // This will happen regardless of whether the image ever contained
        // encoded data or not.
        let mut img = unwrap_or_return_val!(ImageWrapper::load_from_file(path, false), false);

        // Scramble the image.
        img.scramble();

        // If the file was successfully scrambled then it can be removed from
        // the entry list, otherwise we will need to try again later.
        let res = img.save(path);

        // Next, we need to remove the ZTXT chunk from the PNG file. This will
        // act to further camouflage the modifications.
        if utils::remove_ztxt_chunk(path) {
            // We need to add the IEND chunk back into the PNG file
            // in order for it to be considered valid.
            let mut f = unwrap_or_return_val!(File::options().append(true).open(path), false);

            let end = utils::IEND.to_vec();
            let _wb = f.write(&end).unwrap();
        }

        // Spoof the file last modification time of the data file to make it
        // appear as though it were never changed.
        if let Ok(time) = mtime {
            let _ = filetime::set_file_mtime(path, time);
        }

        // Toggle the read-only state again, if needed.
        if is_read_only {
            let _ = utils::toggle_file_read_only_state(path);
        }

        res.is_ok()
    }

    #[allow(dead_code)]
    fn print_locker_list(&self) {
        println!("Total entries: {}", self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            println!("Entry {} : {}", i, e);
        }
    }

    fn read_locker_file(&mut self) -> Result<()> {
        const ENTRY_SIZE: usize = 33;

        let path = Locker::get_locker_file_path()?;
        if !utils::path_exists(&path) {
            return Ok(());
        }

        // This will indicate a corrupted locker file.
        let metadata = utils::get_file_metadata(&path)?;
        if metadata.len() % (ENTRY_SIZE as u64) != 0 {
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
        #[cfg(test)]
        {
            if self.clear_on_exit {
                self.clear_locks();
                return;
            }
        }

        // If writing the locker file failed, exit immediately.
        if self.write_locker_file().is_err() {
            if let Ok(path) = Locker::get_locker_file_path() {
                _ = fs::remove_file(path);
            }
            return;
        }

        // Next, we need to set the data files modified date to be the same
        // as the executable file.
        // This will stop people who are not aware of what this tool is used
        // for identifying the use of this file, which is to avoid the same people
        // from repeatedly trying to break the passwords.
        let bin_path = unwrap_or_return!(Locker::get_binary_path());
        let data_path = unwrap_or_return!(Locker::get_locker_file_path());

        // Set the file last modification time of the data file.
        let metadata = unwrap_or_return!(utils::get_file_metadata(&bin_path));
        let mtime = FileTime::from_last_modification_time(&metadata);
        let _ = utils::set_file_last_modified_timestamp(&data_path, mtime);
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
            utils::u8_array_to_hex(&self.hash),
            self.attempts
        )
    }
}

#[cfg(test)]
mod tests_locker {
    use crate::{
        hashers,
        test_utils::{FileCleaner, TestUtils},
        utils,
    };

    use serial_test::serial;

    use super::{Locker, LockerEntry};

    /// The default entry for use when hashing.
    const HASH_STR: &str = "ElPsyKongroo";
    /// The sub directory to the test files.
    const BASE: [&str; 1] = ["locker"];

    /*
     * Note that these tests should be run in serial mode as reading and
     * writing from files can be flakey with threads.
     */

    /// Create a file locker instance, or panic if it fails.
    fn create_locker_instance_or_assert() -> Locker {
        let locker = Locker::new();
        assert!(locker.is_ok(), "could not initialize locker instance");

        locker.unwrap()
    }

    #[test]
    #[serial]
    fn test_is_file_locked() {
        let hash = hashers::sha3_256_string(HASH_STR);

        let mut locker = create_locker_instance_or_assert();
        locker.clear_on_exit = true;

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
    #[serial]
    fn test_read_write_locker_file() {
        let hash = hashers::sha3_256_string(HASH_STR);
        let entry = LockerEntry::new(&hash, 3);

        // The locker instance should save the entries when goes out of scope.
        {
            let mut locker = create_locker_instance_or_assert();
            locker.entries.clear();
            locker.entries.push(entry.clone());
        }

        // The new locker instance should read the prior list of entries upon creation.
        let locker = create_locker_instance_or_assert();

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
        assert!(
            *entry2.unwrap() == entry,
            "entry was not the same after unloading and reloading"
        );
    }

    #[test]
    #[serial]
    fn test_update_access_attempts() {
        let tu = TestUtils::new(&BASE);

        let original_path = tu.get_in_file("dummy.png");
        let hash = if let Ok(h) = hashers::sha3_256_file(&original_path) {
            h
        } else {
            panic!("failed to create file hash");
        };

        let mut locker = create_locker_instance_or_assert();
        locker.clear_on_exit = true;

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
        assert!(
            entry.unwrap().attempts == 0,
            "entry was found in the entries list, but the attempts field was invalid"
        );

        // Next we need to test of the entry correctly updates.
        locker.update_file_lock(&original_path, &hash);
        let entry = locker.get_entry_by_hash(&hash);
        assert!(
            entry.unwrap().attempts == 1,
            "entry was found in the entries list, but the attempts field was invalid"
        );
    }

    #[test]
    #[serial]
    fn test_file_lock() {
        let tu = TestUtils::new(&BASE);

        let old_path = tu.get_in_file("dummy.png");
        let copy_path = tu.copy_in_file_to_random_out("dummy.png", "png");

        let mut f = FileCleaner::new();
        f.add(&copy_path);

        // Set the copy file as read-only.
        if let Err(_e) = utils::toggle_file_read_only_state(&copy_path) {
            panic!("Failed to set the read-only state of the copied file");
        }

        // Get the last modified timestamp of the original file.
        let old_timestamp = if let Ok(ft) = utils::get_file_last_modified_timestamp(&old_path) {
            ft
        } else {
            panic!("Failed to get the timestamp of the original file");
        };

        // Compute the hash of the original file.
        let old_hash = if let Ok(h) = hashers::sha3_256_file(&old_path) {
            h
        } else {
            panic!("failed to create file hash");
        };

        let mut locker = create_locker_instance_or_assert();
        locker.clear_on_exit = true;

        // Add the entry with 4 (0th is the first attempt) attempts. The next failed attempt will lock the file.
        locker.entries.push(LockerEntry::new(&old_hash, 3));
        locker.update_file_lock(&copy_path, &old_hash);

        // The file hash should have changed.
        let new_hash = if let Ok(h) = hashers::sha3_256_file(&copy_path) {
            h
        } else {
            panic!("failed to create file hash");
        };
        assert!(
            new_hash != old_hash,
            "the hash of the copy and original file are the same, no file locking took place"
        );

        // The (old) file hash should no longer be in the entries list.
        let entry = locker.get_entry_by_hash(&old_hash);
        assert!(
            entry.is_none(),
            "entry was found in the entries list, after it should have been removed"
        );

        // The file should also no longer contain a zTXt chunk.
        let ztxt_start = utils::find_png_ztxt_chunk_start(&copy_path);
        assert!(
            ztxt_start.is_none(),
            "a zTXt chunk was found in the locked PNG file, it should have been removed"
        );

        let locked_read_only = utils::get_file_read_only_state(&copy_path);
        assert!(
            locked_read_only.is_ok(),
            "failed to read the read-only state of the locked file"
        );
        assert!(
            locked_read_only.unwrap(),
            "the read-only state of the file was not restored after locking"
        );

        // Get the last modified timestamp of the copied file.
        let copy_timestamp = if let Ok(ft) = utils::get_file_last_modified_timestamp(&copy_path) {
            ft
        } else {
            panic!("Failed to get the timestamp of the original file");
        };

        assert!(
            copy_timestamp == old_timestamp,
            "the timestamp of the copied file is different than that of the original file"
        );
    }
}
