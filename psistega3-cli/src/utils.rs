use std::{fs::{File, self}, io::Read, path::PathBuf};

use crate::{error::*, file_attempts::*};

pub(crate) fn get_executable_path() -> Result<PathBuf> {
    match std::env::current_exe() {
        Ok(p) => Ok(p),
        Err(_) => Err(Error::DataFilePath),
    }
}

pub(crate) fn get_data_file_path() -> Result<PathBuf> {
    // Build the path. Disregard the executable file name and append the
    // data file name.
    let mut path = get_executable_path()?;
    path.pop();
    path.push("data.dat");

    Ok(path)
}

pub(crate) fn create_data_file() -> Result<()> {
    let path = get_data_file_path()?;
    if !path.exists() && File::create(path).is_err() {
        return Err(Error::DataFileCreation);
    }

    Ok(())
}

pub(crate) fn read_data_file() -> Result<Vec<FileAttempts>> {
    let path = get_data_file_path()?;
    if !path.exists() {
        return Err(Error::DataFilePath);
    }

    let mut attempts: Vec<FileAttempts> = Vec::new();

    // The file will automatically be closed when it goes out of scope.
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return Err(Error::DataFileRead);
        }
    };
    let mut buffer = [0u8; 33];

    // Loop until we have read the entire file (in chunks).
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 || n < 33 {
            break;
        }

        let fa = FileAttempts::new(buffer[..n-1].to_vec(), buffer[n]);

        attempts.push(fa);
    }

    Ok(attempts)
}

pub(crate) fn get_file_metadata(path: &PathBuf) -> Result<fs::Metadata> {
    match fs::metadata(path) {
        Ok(m) => Ok(m),
        Err(_) => Err(Error::FileMetadata),
    }
}
