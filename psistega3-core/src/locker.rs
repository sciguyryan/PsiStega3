use crate::{error::*, utils};

use filetime::FileTime;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    time::SystemTime,
};

// TODO: make this private for release.
// TODO: allocate enough space for 100 entries.
pub struct Locker {
    entries: Vec<Entry>,
    rng: ChaCha20Rng,
}

impl Locker {
    pub fn new() -> Result<Self> {
        let mut l = Self {
            entries: Vec::new(),
            rng: ChaCha20Rng::from_entropy(),
        };

        l.read_locker_file()?;

        //println!("fa = {}", l.entries[0].last);

        Ok(l)
    }

    fn create_locker_file(&mut self) -> Result<File> {
        let path = Locker::get_locker_file_path();
        if path.is_err() {
            return Err(Error::LockerFilePath);
        }

        let path = path.unwrap();

        // Now we need to preload the entries list with junk data.
        if !path.exists() {
            self.generate_dummy_entries();
        }

        let f = match File::create(path) {
            Ok(f) => f,
            Err(_) => return Err(Error::LockerFileCreation),
        };

        Ok(f)
    }

    fn generate_dummy_entry(&mut self) -> Entry {
        // Create a dummy hash.
        let mut hash: Vec<u8> = Vec::with_capacity(32);
        utils::fast_fill_vec_random(&mut hash, &mut self.rng);

        // Create a dummy date between the start of the UNIX
        // epoch and yesterday.
        // As this date is in the past, it may always be overwritten.
        let now = Locker::get_days_since_epoch();
        let days = self.rng.gen_range(0..now).to_le_bytes();

        Entry::new(&hash, 128, &days)
    }

    fn generate_dummy_entries(&mut self) {
        for _ in 0..100 {
            let dummy = self.generate_dummy_entry();
            self.entries.push(dummy);
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

    fn get_days_since_epoch() -> u32 {
        // The number of days since the UNIX epoch.
        return match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => Locker::seconds_as_days(n.as_secs()),
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        } as u32;
    }

    fn seconds_as_days(seconds: u64) -> u32 {
        let s = seconds as f32 / (60 * 60 * 24) as f32;
        s.floor() as u32
    }

    fn read_locker_file(&mut self) -> Result<()> {
        let path = Locker::get_locker_file_path()?;
        if !path.exists() {
            return Ok(());
        }

        // The file will automatically be closed when it goes out of scope.
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Err(Error::LockerFileRead);
            }
        };

        // This will hold the chunk of data that is being read.
        let mut buffer = [0u8; 37];

        // Loop until we have read the entire file (in chunks).
        let mut i = 128u8;
        loop {
            let n = file.read(&mut buffer).unwrap();

            // Either there are not enough bytes to
            // create a file access struct instance.
            if n < 37 {
                break;
            }

            let mut last_vec = buffer[33..].to_vec();
            for b in &mut last_vec {
                *b ^= i;
            }

            // Construct the entry based on the read bytes.
            let fa = Entry::new(&buffer[..32], buffer[32] ^ i, &last_vec);
            self.entries.push(fa);

            i -= 1;
        }

        //println!("fa = {}", self.entries[0].last);

        Ok(())
    }

    fn write_locker_file(&mut self) -> Result<()> {
        let mut file = self.create_locker_file()?;

        // Iterate over the entries in the attempts cache.
        let mut i = 128u8;
        for entry in &self.entries {
            let mut vec = entry.hash.clone();
            vec.push(entry.attempts ^ i);

            // If we hit an error then we will stop
            // writing the file immediately.
            if file.write(&vec).is_err() {
                return Err(Error::LockerFileWrite);
            }

            // XOR the last modified time bytes.
            let mut bytes = entry.last.to_le_bytes();
            for b in &mut bytes {
                *b ^= i;
            }

            // If we hit an error then we will stop
            // writing the file immediately.
            if file.write(&bytes).is_err() {
                return Err(Error::LockerFileWrite);
            }

            i -= 1;
        }

        Ok(())
    }
}

impl Drop for Locker {
    fn drop(&mut self) {
        _ = self.write_locker_file();

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

        // In theory this should never happen... but just in case.
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
struct Entry {
    hash: Vec<u8>,
    attempts: u8,
    last: u32,
}

impl Entry {
    pub fn new(hash: &[u8], attempts: u8, last: &[u8]) -> Self {
        assert!(
            last.len() == 4,
            "Invalid number of bytes to represent a u32 value."
        );
        let arr = <[u8; 4]>::try_from(last).unwrap();

        Self {
            hash: hash.to_vec(),
            attempts,
            last: u32::from_le_bytes(arr),
        }
    }
}
