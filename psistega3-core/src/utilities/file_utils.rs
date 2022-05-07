use crate::{
    error::{Error, Result},
    macros::*,
    utilities::misc_utils,
};

use filetime::FileTime;
use memmap2::Mmap;
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

#[allow(dead_code)]
pub(crate) enum PngChunkType {
    Bkgd,
    Idat,
    Iend,
    Ztxt,
}

/// The bKGD chunk header of a PNG file.
const BKGD: [u8; 4] = [0x62, 0x4b, 0x47, 0x44];

/// The IDAT chunk header of a PNG file.
const IDAT: [u8; 4] = [0x49, 0x44, 0x41, 0x54];

/// The IEND chunk header of a PNG file.
const IEND: [u8; 4] = [0x49, 0x45, 0x4e, 0x44];

/// The zTXt chunk header of a PNG file.
const ZTXT: [u8; 4] = [0x7a, 0x54, 0x58, 0x74];

/// Attempts to find the first position of a chunk type within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `chunk_type` - The type of chunk to find.
///
pub(crate) fn find_png_chunk_start(path: &str, chunk_type: PngChunkType) -> Option<usize> {
    let file = unwrap_or_return_val!(File::open(path), None);

    // Create a read-only memory map of the file as it should improve
    // the performance of this function.
    let mmap = unsafe { unwrap_or_return_val!(Mmap::map(&file), None) };

    let seq = match chunk_type {
        PngChunkType::Bkgd => &BKGD,
        PngChunkType::Idat => &IDAT,
        PngChunkType::Iend => &IEND,
        PngChunkType::Ztxt => &ZTXT,
    };

    // The chunk is present then the index of the header will be returned.
    let index = misc_utils::find_subsequence(&mmap, seq)?;

    // The start of a chunk is always four bytes before the header.
    // The initial four bytes of the chunk give the length of the chunk.
    Some(index - 4)
}

/// Generate a bKGD chunk for a PNG.
///
/// # Arguments
///
/// * `data` - A slice of u8 bytes that represent the RGB values to be used.
///
/// `Note:` as PsiStega3 only outputs images with a 32-bit colour depth,
/// this function will assert if there are not exactly 6 bytes provided as data.
///
pub(crate) fn generate_png_bkgd_chunk(data: &[u8]) -> Vec<u8> {
    assert_eq!(
        data.len(),
        6,
        "the bKGD data chunk must have exactly 6 bytes for a 32-bit PNG file"
    );

    // bKGD chunk.
    // See: http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    // The first four bytes will hold the length, which will be updated
    // below.
    let mut chunk: Vec<u8> = vec![0, 0, 0, 0];
    chunk.extend_from_slice(&BKGD);
    chunk.extend_from_slice(data);

    // Update the chunk length data. This excludes the length
    // of the chunk (4 bytes) and the chunk type header (4 bytes).
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

/// Get the data of a PNG chunk's data segment.
///
/// # Arguments
///
/// * `data` - The contents of the PNG chunk.
///
pub(crate) fn get_png_chunk_data(data: &[u8]) -> Option<&[u8]> {
    let data_len = get_png_chunk_length(data)?;

    let start = 8;
    let end = start + data_len as usize;

    // This should never happen.
    if end >= data.len() {
        return None;
    }

    Some(&data[start..end])
}

/// Get the length of a PNG chunk's data segment.
///
/// # Arguments
///
/// * `data` - The contents of the PNG chunk.
///
pub(crate) fn get_png_chunk_length(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }

    // The length of the chunk's data segment is given by the first four
    // bytes of the chunk. The unwrap is safe here since we have verified
    // the data length above.
    let chunk_len_arr = <[u8; 4]>::try_from(&data[..4]).unwrap();
    Some(u32::from_be_bytes(chunk_len_arr))
}

/// Insert (or replace) a bKGD chunk within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `data` - The contents of the chunk.
///
pub fn insert_or_replace_png_bkgd_chunk(path: &str, data: &[u8]) -> Result<()> {
    // bKGD chunk.
    // See: http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    // The chunk must be after the PLTE chunk, and before the first IDAT chunk.

    let idat = find_png_chunk_start(path, PngChunkType::Idat);
    if idat.is_none() {
        return Err(Error::ImageMalformed);
    }

    // Generate the data for the chunk.
    let chunk = generate_png_bkgd_chunk(data);

    // Does a bKGD chunk already exists within the PNG file?
    // If it does then we want to remove it, before replacing it
    // with our own data.
    if find_png_chunk_start(path, PngChunkType::Bkgd).is_some() && !remove_png_bkgd_chunk(path) {
        return Err(Error::FileWrite);
    }

    // Splice the chunk data into the image file.
    splice_data_into_file(path, idat.unwrap() as u64, &chunk)
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

/// Read a raw (complete) PNG chunk.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `chunk_type` - The chunk type of be read.
///
/// `Note:` this function is only designed to read the **first** instance of the chunk present within the file.
///
fn read_png_chunk_raw(path: &str, chunk_type: PngChunkType) -> Option<Vec<u8>> {
    // If we have a chunk present then the index of
    // the header will be returned.
    let start = find_png_chunk_start(path, chunk_type)?;

    // Create a read-only memory map of the file.
    let file = unwrap_or_return_val!(File::open(path), None);
    let mmap = unsafe { unwrap_or_return_val!(Mmap::map(&file), None) };

    // The start of a chunk is always four bytes behind the chunk type bytes.
    // The initial four bytes of the chunk indicate the length of the data
    // portion of the chunk.
    let len_bytes = &mmap[start..start + 4];
    if len_bytes.len() < 4 {
        return None;
    }

    // Since we have confirmed there are at least four bytes
    // available, this unwrap is safe since it can't fail.
    let chunk_len_arr = <[u8; 4]>::try_from(len_bytes).unwrap();
    let chunk_len = u32::from_be_bytes(chunk_len_arr);

    // The end of the chunk will be found by taking the start index of the chunk.
    // Next, add four bytes for the chunk length, then four bytes for the chunk
    // header, next the data that makes up the chunk, and finally four more bytes
    // for the CRC checksum.
    let end = start + 8 + chunk_len as usize + 4;

    // This should never happen, and it would indicate a malformed PNG file.
    if end >= mmap.len() {
        return None;
    }

    // Return the chunk data, as a vector of u8 values.
    Some(mmap[start..end].to_vec())
}

/// Attempts to read the bKGD chunk of a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn read_png_bkgd_chunk_data(path: &str) -> Option<Vec<u8>> {
    read_png_chunk_raw(path, PngChunkType::Bkgd)
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

/// Remove a bKGD chunk from within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn remove_png_bkgd_chunk(path: &str) -> bool {
    let chunk = if let Some(c) = read_png_chunk_raw(path, PngChunkType::Bkgd) {
        c
    } else {
        return false;
    };

    // Next, we need to read the length of the chunk data. For our uses
    // there should always be 6 bytes, but better to be safe here.
    let chunk_len = if let Some(len) = get_png_chunk_length(&chunk) {
        len
    } else {
        return false;
    };

    // 4 bytes for the length of the chunk's data,
    // 4 bytes for the chunk header,
    // the number of bytes representing the data,
    // 4 more bytes for the CRC checksum.
    let full_len = (8 + chunk_len + 4) as u64;

    // The unwrap is safe here since we know that the chunk must exist.
    let start_index = find_png_chunk_start(path, PngChunkType::Bkgd).unwrap();

    // Remove the file segment.
    remove_file_segment(path, start_index as u64, full_len).is_ok()
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
