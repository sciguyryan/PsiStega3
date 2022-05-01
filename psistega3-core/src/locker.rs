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
}

impl Locker {
    pub fn new() -> Result<Self> {
        let mut l = Self {
            entries: Vec::with_capacity(20),
        };

        l.read_locker_file()?;

        //l.print_locker_list();

        Ok(l)
    }

    #[cfg(not(debug_assertions))]
    fn cipher_slice(slice: &mut [u8], xor: u8) {
        for b in slice.iter_mut() {
            *b = !(*b ^ xor)
        }
    }

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

    fn get_entry_index_by_hash(&self, hash: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.hash == hash)
    }

    fn get_entry_by_hash(&self, hash: &[u8]) -> Option<&LockerEntry> {
        self.entries.iter().find(|e| e.hash == hash)
    }

    fn get_entry_by_hash_mut(&mut self, hash: &[u8]) -> Option<&mut LockerEntry> {
        self.entries.iter_mut().find(|e| e.hash == hash)
    }

    fn get_executable_path() -> Result<PathBuf> {
        match std::env::current_exe() {
            Ok(p) => Ok(p),
            Err(_) => Err(Error::LockerFilePath),
        }
    }

    fn get_file_metadata(path: &PathBuf) -> Result<fs::Metadata> {
        match fs::metadata(path) {
            Ok(m) => Ok(m),
            Err(_) => Err(Error::FileMetadata),
        }
    }

    fn get_locker_file_path() -> Result<PathBuf> {
        // Build the path. Disregard the executable file name and append the
        // data file name.
        let mut path = Locker::get_executable_path()?;
        path.pop();
        path.push("data.dat");

        Ok(path)
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

    pub fn lock_file(&mut self, file_path: &str) -> bool {
        use crate::image_wrapper::ImageWrapper;

        // If the path does not currently exist then we cannot lock it,
        // this means we shouldn't remove it from the list.
        if !utils::path_exists(file_path) {
            return false;
        }

        let path = PathBuf::from(file_path);

        // This should never happen, but if it does then
        // the entry should be removed from the list.
        // It isn't possible to lock a directory.
        if path.is_dir() {
            return true;
        }

        // We do not want to lock the file after we are done with this
        // section of the code. Rust will automatically close the file
        // when the reference is dropped.
        let mut is_read_only = false;
        let mtime: FileTime;
        {
            // Get the metadata for the file.
            let metadata = unwrap_or_return_val!(Locker::get_file_metadata(&path), false);

            // If the file is read only, then we need to unset that flag.
            if metadata.permissions().readonly() {
                metadata.permissions().set_readonly(false);
                is_read_only = true;
            }

            mtime = FileTime::from_last_modification_time(&metadata);
        }

        // Now we need to ensure that the file can never be decoded.
        // This will happen regardless of whether the image ever contained
        // encoded data or not.
        let mut img = unwrap_or_return_val!(ImageWrapper::load_from_file(file_path, false), false);

        // Scramble the image.
        img.scramble();

        // If the file was successfully scrambled then it can be removed from
        // the entry list, otherwise we will need to try again later.
        let res = img.save(file_path);

        // Next, we need to remove the ZTXT chunk from the PNG file. This will
        // act to further camouflage the modifications.
        if Locker::remove_ztxt_chunk(file_path) {
            // We need to add the IEND chunk back into the PNG file
            // in order for it to be considered valid.
            let mut f = unwrap_or_return_val!(File::options().append(true).open(file_path), false);

            let end = utils::IEND.to_vec();
            let _wb = f.write(&end).unwrap();
        }

        // Spoof the file last modification time of the data file to make it
        // appear as though it were never changed.
        _ = filetime::set_file_mtime(file_path, mtime);

        // Toggle the read-only state again, if needed.
        if is_read_only {
            Locker::toggle_read_only(file_path);
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
        if !path.exists() {
            return Ok(());
        }

        // This will indicate a corrupted locker file.
        let metadata = Locker::get_file_metadata(&path)?;
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

    fn remove_ztxt_chunk(path: &str) -> bool {
        let index = utils::find_png_ztxt_chunk_start(path);
        if index.is_none() {
            return false;
        }

        // The new length should be the index of the ZTXT chunk less four bytes.
        // The latter four bytes are the bytes that would indicate the ZTXT
        // chunk length.
        let new_len = index.unwrap() - 4;

        // Truncate the file to the new length.
        // Note that we are not appending the IEND chunk here,
        // which must be done in order for the PNG file to be valid.
        utils::truncate_file(path, new_len as u64).is_ok()
    }

    fn toggle_read_only(path: &str) {
        let pb = PathBuf::from(path);

        // Get the metadata for the file.
        let metadata = unwrap_or_return!(Locker::get_file_metadata(&pb));

        // If the file is read only, then we need to unset that flag.
        let read_only = metadata.permissions().readonly();
        metadata.permissions().set_readonly(!read_only);
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
                println!("File successfully locked.");
                self.force_clear_file_lock(hash);
            } else {
                // TODO: figure out if anything should be done here.
                println!("Failed to lock file.");
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
        // If writing the locker file failed, exit immediately.
        // TODO: it may be prudent to delete the file if the file isn't locked.
        if self.write_locker_file().is_err() {
            return;
        }

        // Next, we need to set the data files modified
        // date to be the same as the executable file.
        // This will stop people who are not aware of
        // what this tool is used for identifying the use
        // of this file, which is to avoid the same people
        // from repeatedly trying to break the passwords.
        let exec_path = unwrap_or_return!(Locker::get_executable_path());
        let data_path = unwrap_or_return!(Locker::get_locker_file_path());

        // Set the file last modification time of the data file.
        let metadata = unwrap_or_return!(Locker::get_file_metadata(&exec_path));
        let mtime = FileTime::from_last_modification_time(&metadata);
        _ = filetime::set_file_mtime(data_path, mtime);
    }
}

#[derive(Debug)]
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
