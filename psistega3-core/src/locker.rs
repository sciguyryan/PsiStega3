use crate::{error::*, hashers, utils};

use filetime::FileTime;
use rand::prelude::SliceRandom;
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
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
        //println!("fa = {}", l.entries[0].last);

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

    fn create_locker_file(&mut self) -> Result<File> {
        let path = Locker::get_locker_file_path();
        if path.is_err() {
            return Err(Error::LockerFilePath);
        }
        let path = path.unwrap();

        let file = match File::create(path) {
            Ok(f) => f,
            Err(_) => return Err(Error::LockerFileCreation),
        };

        Ok(file)
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

    fn get_locker_file_path() -> Result<PathBuf> {
        // Build the path. Disregard the executable file name and append the
        // data file name.
        let mut path = Locker::get_executable_path()?;
        path.pop();
        path.push("data.dat");

        Ok(path)
    }

    fn get_file_metadata(path: &PathBuf) -> Result<fs::Metadata> {
        match fs::metadata(path) {
            Ok(m) => Ok(m),
            Err(_) => Err(Error::FileMetadata),
        }
    }

    fn clear_file_lock(&mut self, hash: &[u8]) {
        if let Some(i) = self.get_entry_index_by_hash(hash) {
            // The hash exists within the list so we should remove it.
            self.entries.remove(i);
        }

        // The hash is not in the entry list, we do not need to
        // do anything here.
    }

    pub fn maybe_clear_file_lock(&mut self, hash: &[u8]) {
        // If the file has been locked then we can't unlock it.
        if self.is_file_locked(hash) {
            return;
        }

        self.clear_file_lock(hash);
    }

    pub fn maybe_update_file_lock(&mut self, path: &str, hash: &[u8]) {
        if self.is_file_locked(hash) {
            // The entry exists within the list, has hit the attempt limited
            // but hasn't been locked. We need to attempt to lock the file.
            // If successful then it can be removed from the list.
            if self.lock_file(path) {
                self.clear_file_lock(hash);
            } else {
                // TODO: figure out if anything should be done here.
            }
        } else if let Some(entry) = self.get_entry_by_hash_mut(hash) {
            // The entry exists within the entries list.
            // We need to update the counter.
            (*entry).attempts += 1;
        } else if let Ok(h) = hashers::sha3_256_file(path) {
            // The entry does not exists within the entries list.
            // We need to add it.
            self.entries.push(LockerEntry::new(&h, 0));
        } else {
            // Failed to add the entry to the list.
            // TODO: figure out what needs to be done here.
        }
    }

    pub fn lock_file(&mut self, file_path: &str) -> bool {
        use crate::image_wrapper::ImageWrapper;

        // If the path does not currently exist then we cannot lock it,
        // this means we shouldn't remove it from the list.
        let path = Path::new(file_path);
        if !path.exists() {
            return false;
        }

        // This should never happen, but if it does then
        // the entry should be removed from the list. We can't lock a directory.
        if path.is_dir() {
            return true;
        }

        // We do not want to lock the file after we are done with this
        // section of the code. Rust will automatically close the file
        // when the reference is dropped.
        {
            let f = File::open(path);
            if f.is_err() {
                return false;
            }
            let f = f.unwrap();

            // Get the metadata for the file.
            let metadata = f.metadata();
            if metadata.is_err() {
                return false;
            }
            let metadata = metadata.unwrap();

            // If the file is read only, then we need to unset that flag.
            if metadata.permissions().readonly() {
                metadata.permissions().set_readonly(false);
            }
        }

        // Now we need to ensure that the file can never be decoded.
        // This will happen regardless of whether the image ever contained
        // encoded data or not.
        let img = ImageWrapper::load_from_file(file_path, false);
        if img.is_err() {
            return false;
        }
        let mut img = img.unwrap();

        // Scramble the image.
        img.scramble();

        // If the file was successfully scrambled then it can be removed from
        // the entry list, otherwise we will need to try again later.
        img.save(file_path).is_ok()
    }

    pub fn is_file_locked(&self, hash: &[u8]) -> bool {
        // A file is considered locked if 5 more more attempts have been made
        // to decode it, where the decryption was unsuccessful, in other words
        // where an invalid key had been used.
        // Note that the entry is added to the entry list upon the first
        // unsuccessful attempt, which means that the 0th attempt is actually
        // the first one.
        if let Some(entry) = self.get_entry_by_hash(hash) {
            entry.attempts >= 4
        } else {
            false
        }
    }

    #[allow(dead_code)]
    #[cfg(debug_assertions)]
    fn print_locker_list(&self) {
        println!("Total entries: {}", self.entries.len());
        for (i, e) in self.entries.iter().enumerate() {
            println!("Entry {} : {}", i, e);
        }
    }

    #[cfg(debug_assertions)]
    fn inject_debug_entries(&mut self) {
        for c in ["A", "B", "C"] {
            let entry = LockerEntry::new(&hashers::sha3_256_string(&str::repeat(c, 4)), 0);
            self.entries.push(entry);
        }
    }

    fn read_locker_file(&mut self) -> Result<()> {
        const ENTRY_SIZE: usize = 33;

        let path = Locker::get_locker_file_path()?;
        if !path.exists() {
            #[cfg(debug_assertions)]
            self.inject_debug_entries();

            return Ok(());
        }

        // This will indicate a corrupted locker file.
        let metadata = Locker::get_file_metadata(&path)?;
        if metadata.len() % (ENTRY_SIZE as u64) != 0 {
            return Err(Error::LockerFileRead);
        }

        /*let fe = File::open(path.clone()).unwrap();
        let mut reader = std::io::BufReader::new(fe);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        println!("{}", utils::entropy(&buffer));*/

        // The file will automatically be closed when it goes out of scope.
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Err(Error::LockerFileRead),
        };

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
        let exec_path = Locker::get_executable_path();
        let data_path = Locker::get_locker_file_path();
        if exec_path.is_err() || data_path.is_err() {
            return;
        }

        let exec_path = exec_path.unwrap();
        let data_path = data_path.unwrap();

        let metadata = Locker::get_file_metadata(&exec_path);
        if metadata.is_err() {
            return;
        }
        let metadata = metadata.unwrap();

        // Set the file last modification time of the data file.
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
