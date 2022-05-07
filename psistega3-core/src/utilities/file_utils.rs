use crate::{
    error::{Error, Result},
    macros::*,
};

use filetime::FileTime;
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

/// Get the last modified timestamp as a [`FileTime`] instance.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn get_file_last_modified(path: &str) -> Result<FileTime> {
    let meta = get_file_metadata(path)?;

    Ok(FileTime::from_last_modification_time(&meta))
}

/// Get the metadata for a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn get_file_metadata(path: &str) -> Result<Metadata> {
    let p = Path::new(&path);

    if !p.exists() || !p.is_file() {
        return Err(Error::FileMetadata);
    }

    if let Ok(meta) = p.metadata() {
        Ok(meta)
    } else {
        Err(Error::FileMetadata)
    }
}

/// Get the read-only state of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn get_file_read_only_state(path: &str) -> Result<bool> {
    // If the file doesn't exist then it can't be read-only.
    if !path_exists(path) {
        return Ok(false);
    }

    let meta = get_file_metadata(path)?;

    Ok(meta.permissions().readonly())
}

/// Check if the specified path is valid and exists.
///
/// # Arguments
///
/// * `path` - The path to be checked.
///
#[inline]
pub(crate) fn path_exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Read a file into a u8 vector.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn read_file_to_u8_vector(path: &str) -> Result<Vec<u8>> {
    if !path_exists(path) {
        return Err(Error::PathInvalid);
    }

    let mut file = unwrap_or_return_err!(File::open(&path), Error::File);
    let mut buffer = Vec::new();
    match file.read_to_end(&mut buffer) {
        Ok(_) => Ok(buffer),
        Err(_) => Err(Error::FileRead),
    }
}

pub fn remove_file_segment(path: &str, remove_start: u64, remove_length: u64) -> Result<()> {
    let mut file = unwrap_or_return_err!(
        File::options().read(true).write(true).open(path),
        Error::FileOpen
    );

    /*
        The data will essentially be split into three segments.
        The first segments will contain everything before the split point,
          the second segments will contain the data to be removed,
          the third segments will contain the data to be preserved.
    */

    // Calculate the length of the file, after the data has been removed.
    let meta = unwrap_or_return_err!(file.metadata(), Error::FileMetadata);
    let new_len = meta.len() - remove_length;

    // Set the cursor to the position where the data to be kept begins.
    let remove_end = remove_start + remove_length;
    unwrap_or_return_err!(file.seek(SeekFrom::Start(remove_end)), Error::FileRead);

    // Read the chunk into a buffer.
    let mut buf: Vec<u8> = Vec::new();
    unwrap_or_return_err!(file.read_to_end(&mut buf), Error::FileRead);

    // Set the cursor to the position of the start of the section to be removed.
    unwrap_or_return_err!(file.seek(SeekFrom::Start(remove_start)), Error::FileRead);

    // Write the saved chunk back into the file.
    if file.write_all(&buf).is_err() {
        return Err(Error::FileWrite);
    }

    // Truncate the file to the new length, otherwise we will have duplicate
    // data at the end of the file.
    if file.set_len(new_len).is_err() {
        return Err(Error::FileTruncate);
    }

    Ok(())
}

/// Sets the last modified timestamp of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `timestamp` - The [`FileTime`] timestamp to set as the last modified date of the file.
///
pub(crate) fn set_file_last_modified(path: &str, timestamp: FileTime) -> Result<()> {
    if filetime::set_file_mtime(path, timestamp).is_ok() {
        Ok(())
    } else {
        Err(Error::FileMetadata)
    }
}

/// Sets the last modified timestamp of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `splice_at` - The point at which the data should be spliced into the file.
/// * `data` - The data which should be spliced into the file.
///
pub(crate) fn splice_data_into_file(path: &str, splice_at: u64, data: &[u8]) -> Result<()> {
    let mut file = unwrap_or_return_err!(
        File::options().read(true).write(true).open(path),
        Error::FileOpen
    );

    /*
        The data will be split into two chunks.
        The first chunk will contain everything before the split point,
          the second chunk will contain everything after it.
        The second chunk will be held in a buffer until the spliced data is
          written into the file, it will then be written back into the file.
    */

    let seek = SeekFrom::Start(splice_at);
    unwrap_or_return_err!(file.seek(seek), Error::FileRead);

    let mut buf: Vec<u8> = Vec::new();
    unwrap_or_return_err!(file.read_to_end(&mut buf), Error::FileRead);
    unwrap_or_return_err!(file.seek(seek), Error::FileRead);

    if file.write_all(data).is_err() || file.write_all(&buf).is_err() {
        return Err(Error::FileWrite);
    }

    Ok(())
}

/// Toggles the read-only state of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn toggle_file_read_only_state(path: &str) -> Result<()> {
    // Get the metadata for the file.
    let metadata = get_file_metadata(path)?;

    // If the file is read only, then we need to unset that flag.
    let mut permissions = metadata.permissions();
    permissions.set_readonly(!permissions.readonly());

    // Update the file system.
    match std::fs::set_permissions(path, permissions) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::FileMetadata),
    }
}

/// Write a u8 slice to an output file.
///
/// * `path` - The path to the file.
/// * `bytes` - The slice of u8 values to be written to the file.
///
pub(crate) fn write_u8_slice_to_file(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = unwrap_or_return_err!(File::create(&path), Error::FileCreate);

    // Write the resulting bytes directly into the output file.
    match file.write_all(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::FileWrite),
    }
}
