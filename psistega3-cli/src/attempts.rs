use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use crate::error::*;

use filetime::FileTime;

pub struct Attempts {
    entries: Vec<Entry>
}

impl Attempts {
    pub fn new() -> Result<Self> {
        let mut s = Self {
            entries: Vec::new()
        };

        s.read_data_file()?;

        Ok(s)
    }

    fn create_data_file() -> Result<File> {
        let path = Attempts::get_data_file_path();
        if path.is_err() {
            return Err(Error::DataFilePath);
        }

        match File::create(path.unwrap()) {
            Ok(f) => Ok(f),
            Err(_) => Err(Error::DataFileCreation),
        }
    }

    fn get_data_file_path() -> Result<PathBuf> {
        // Build the path. Disregard the executable file name and append the
        // data file name.
        let mut path = Attempts::get_executable_path()?;
        path.pop();
        path.push("data.dat");

        Ok(path)
    }

    fn get_executable_path() -> Result<PathBuf> {
        match std::env::current_exe() {
            Ok(p) => Ok(p),
            Err(_) => Err(Error::DataFilePath),
        }
    }

    fn get_file_metadata(path: &PathBuf) -> Result<fs::Metadata> {
        match fs::metadata(path) {
            Ok(m) => Ok(m),
            Err(_) => Err(Error::FileMetadata),
        }
    }

    fn read_data_file(&mut self) -> Result<()> {
        let path = Attempts::get_data_file_path()?;
        if !path.exists() {
            return Ok(());
        }

        // The file will automatically be closed when it goes out of scope.
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Err(Error::DataFileRead);
            }
        };

        let mut buffer = [0u8; 33];

        // Loop until we have read the entire file (in chunks).
        loop {
            let n = file.read(&mut buffer).unwrap();

            // Either there are not enough bytes to
            // create a file access struct instance.
            if n < 33 {
                break;
            }

            let fa = Entry::new(buffer[..32].to_vec(), buffer[32]);
            self.entries.push(fa);
        }

        Ok(())
    }

    fn write_data_file(&self) -> Result<()> {
        let mut file = Attempts::create_data_file()?;

        for entry in &self.entries {
            let mut vec = entry.hash.clone();
            vec.push(entry.attempts);

            _ = file.write(&vec);
        }

        Ok(())
    }
}

impl Drop for Attempts {
    fn drop(&mut self) {
        _ = self.write_data_file();

        // Next, we need to set the data files modified
        // date to be the same as the executable file.
        // This will stop people who are not aware of
        // what this tool is used for identifying the use
        // of this file, which is to avoid the same people
        // from repeatedly trying to break the passwords.
        let exec_path = Attempts::get_executable_path();
        let data_path = Attempts::get_data_file_path();
        if exec_path.is_err() || data_path.is_err() {
            return;
        }

        // In theory this should never happen... but just in case.
        let exec_path = exec_path.unwrap();
        let data_path = data_path.unwrap();

        let metadata = Attempts::get_file_metadata(&exec_path);
        if metadata.is_err() {
            return;
        }

        let metadata = metadata.unwrap();

        // Set the file accessed time of the data file.
        //let atime = FileTime::from_last_access_time(&metadata);
        //_ = filetime::set_file_atime(data_path, atime);

        // Set the file last modification time of the data file.
        let mtime = FileTime::from_last_modification_time(&metadata);
        _ = filetime::set_file_mtime(data_path, mtime);
    }
}

#[derive(Debug)]
struct Entry {
    hash: Vec<u8>,
    attempts: u8,
}

impl Entry {
    pub fn new(hash: Vec<u8>, attempts: u8) -> Self {
        Self { hash, attempts }
    }
}
