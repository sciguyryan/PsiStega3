use crate::{
    error::{Error, Result},
    macros::*,
    utilities::misc_utils,
};

use filetime::FileTime;
use std::{
    fs::{File, Metadata},
    path::Path,
};

/// The IEND chunk of a PNG file.
pub(crate) const IEND: [u8; 12] = [0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82];

/// The ZTXT chunk header of a PNG file.
pub(crate) const ZTXT: [u8; 4] = [0x7a, 0x54, 0x58, 0x74];

/// Attempts to find the position of the zTXt chunk within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn find_png_ztxt_chunk_start(path: &str) -> Option<usize> {
    use memmap2::Mmap;

    let file = unwrap_or_return_val!(File::open(path), None);

    // Create a read-only memory map of the file as it should improve
    // the performance of this function.
    let mmap = unsafe { unwrap_or_return_val!(Mmap::map(&file), None) };

    // If we have a ZTXT chunk present then the index of
    // the header will be returned.
    let index = misc_utils::find_subsequence(&mmap, &ZTXT)?;

    // The start of a chunk is always four bytes behind the header.
    // The initial four bytes of the chunk indicate the length of the chunk.
    Some(index - 4)
}

/// Generate a zTXt chunk for a PNG.
///
pub(crate) fn generate_ztxt_chunk(keys: &[String], data: &[Vec<u8>]) -> Vec<u8> {
    assert!(
        keys.len() == data.len(),
        "the key and data vectors must be the same length"
    );

    // zTXt chunk.
    // See: http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    // The first four bytes will hold the length, which will be updated
    // below.
    let mut chunk: Vec<u8> = vec![0, 0, 0, 0];
    chunk.append(&mut String::from("zTXt").into_bytes());

    for i in 0..keys.len() {
        chunk.extend_from_slice(keys[i].as_bytes());
        chunk.push(0); // Separator. Must be a null byte.
        chunk.push(0); // Compression method. Only zero is valid here.
        chunk.extend_from_slice(&data[i]);
    }

    // Update the chunk length data. This excludes the length
    // of the chunk (4 bytes) and the chunk type label (4 bytes).
    let chunk_len = (chunk.len() - 8) as u32;
    for (i, b) in chunk_len.to_be_bytes().iter().enumerate() {
        chunk[i] = *b;
    }

    // Write the CRC for the chunk. This must exclude the bytes indicating
    // the length of the chunk.
    let crc = crate::hashers::crc32_slice(&chunk[4..]);
    let crc_bytes = crc.to_be_bytes();
    chunk.extend_from_slice(&crc_bytes);

    chunk
}

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
    use std::io::Read;

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

/// Attempts to read the zTXt chunk of a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
/// `Note:` This function assumes that the PNG file is valid and not badly malformed.
///
pub(crate) fn read_png_ztxt_chunk_data(path: &str) -> Option<Vec<u8>> {
    use memmap2::Mmap;

    // If we have a zTXt chunk present then the index of
    // the header will be returned.
    let mut start = find_png_ztxt_chunk_start(path)?;

    let file = unwrap_or_return_val!(File::open(path), None);

    // Create a read-only memory map of the file as it should improve
    // the performance of this function.
    let mmap = unsafe { unwrap_or_return_val!(Mmap::map(&file), None) };

    // The start of a chunk is always four bytes behind the chunk type bytes.
    // The initial four bytes of the chunk indicate the length of the data
    // portion of the chunk.
    let len_bytes = &mmap[start..start + 4];
    if len_bytes.len() < 4 {
        return None;
    }

    let chunk_len_arr = <[u8; 4]>::try_from(len_bytes).unwrap();
    let chunk_len = u32::from_be_bytes(chunk_len_arr);

    // We can also skip past the chunk type bytes.
    start += 8;

    // The end of the chunk will be found at the new start index
    // plus the length of the chunk.
    let end = start + chunk_len as usize;

    // Return the chunk data, as a vector of u8 values.
    Some(mmap[start..end].to_vec())
}

/// Attempts to remove a zTXt chunk from a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
/// `Note:` This function assumes that the PNG file is valid and not badly malformed.
///
pub(crate) fn remove_ztxt_chunk(path: &str) -> bool {
    let index = find_png_ztxt_chunk_start(path);
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
    truncate_file(path, new_len as u64).is_ok()
}

/// Sets the last modified timestamp of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn set_file_last_modified(path: &str, timestamp: FileTime) -> Result<()> {
    if filetime::set_file_mtime(path, timestamp).is_ok() {
        Ok(())
    } else {
        Err(Error::FileMetadata)
    }
}

/// Attempt to truncate a set number of bytes from the end of a file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `bytes_to_trim` - The number of bytes to be trimmed from the end of the file.
///
pub(crate) fn truncate_file(path: &str, bytes_to_trim: u64) -> Result<()> {
    let file = unwrap_or_return_err!(File::options().write(true).open(path), Error::File);
    let meta = unwrap_or_return_err!(file.metadata(), Error::FileMetadata);

    // Calculate the new file length.
    let new_len = meta.len() - bytes_to_trim;

    // Truncate the file.
    if file.set_len(new_len).is_err() {
        return Err(Error::FileTruncate);
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
/// * `out_file` - The path to the file.
/// * `bytes` - The slice of u8 values to be written to the file.
///
pub(crate) fn write_u8_slice_to_file(out_file: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    // We have decoded a valid base64 string.
    // Next we need to write the data to the file.
    let mut file = unwrap_or_return_err!(File::create(&out_file), Error::FileCreate);

    // Write the resulting bytes directly into the output file.
    match file.write_all(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::FileWrite),
    }
}
