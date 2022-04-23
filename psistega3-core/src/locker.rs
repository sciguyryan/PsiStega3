use crate::error::*;

use filetime::FileTime;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    time::SystemTime,
};

// TODO: make this private for release.
pub struct Locker {
    entries: Vec<Entry>,
}

impl Locker {
    pub fn new() -> Result<Self> {
        let mut l = Self {
            entries: Vec::new(),
        };

        /*let n = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
        let mut n2 = n.unwrap().as_secs();
        n2 -= (60*60*24*30)+1;

        println!("Seconds = {}", n2);

        let bytes = if cfg!(target_endian = "little") {
            u64::to_le_bytes(n2)
        } else {
            u64::to_be_bytes(n2)
        };

        l.entries.push(Entry::new(&Hashers::sha3_256_string("aaaa"), 255, &bytes));*/

        l.read_locker_file()?;

        Ok(l)
    }

    fn create_locker_file() -> Result<File> {
        let path = Locker::get_locker_file_path();
        if path.is_err() {
            return Err(Error::LockerFilePath);
        }

        match File::create(path.unwrap()) {
            Ok(f) => Ok(f),
            Err(_) => Err(Error::LockerFileCreation),
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

    pub fn get_executable_path() -> Result<PathBuf> {
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

        // The number of seconds since the UNIX epoch.
        let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        };

        let mut buffer = [0u8; 41];

        // Loop until we have read the entire file (in chunks).
        loop {
            let n = file.read(&mut buffer).unwrap();

            // Either there are not enough bytes to
            // create a file access struct instance.
            if n < 41 {
                break;
            }

            // Construct the entry based on the read bytes.
            let fa = Entry::new(&buffer[..32], buffer[32], &buffer[33..]);

            // This should never happen, it would mean that the entry
            // was last modified after the the present.
            let last = if fa.last > now { now } else { fa.last };

            // If the last attempt was more than 30 days ago
            // then we will disregard it.
            if (now - last) > 60 * 60 * 24 * 30 {
                continue;
            }

            self.entries.push(fa);
        }

        Ok(())
    }

    fn write_locker_file(&self) -> Result<()> {
        let mut file = Locker::create_locker_file()?;

        // Iterate over the entries in the attempts cache.
        for entry in &self.entries {
            let mut vec = entry.hash.clone();
            vec.push(entry.attempts);

            // If we hit an error then we will stop
            // writing the file immediately.
            if file.write(&vec).is_err() {
                return Err(Error::LockerFileWrite);
            }

            let bytes = u64::to_le_bytes(entry.last);

            // If we hit an error then we will stop
            // writing the file immediately.
            if file.write(&bytes).is_err() {
                return Err(Error::LockerFileWrite);
            }
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
    last: u64,
}

impl Entry {
    pub fn new(hash: &[u8], attempts: u8, last: &[u8]) -> Self {
        assert!(
            last.len() == 8,
            "Invalid number of bytes to represent a u64 value."
        );
        let arr = <[u8; 8]>::try_from(last).unwrap();

        Self {
            hash: hash.to_vec(),
            attempts,
            last: u64::from_le_bytes(arr),
        }
    }
}
