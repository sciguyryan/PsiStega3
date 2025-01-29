use crate::error::{Error, Result};

use memmap2::Mmap;
use std::fs::File;

use super::{file_utils, misc_utils};

#[allow(dead_code)]
pub enum PngChunkType {
    Bkgd,
    Idat,
}

/// The bKGD chunk header of a PNG file.
const BKGD: [u8; 4] = [0x62, 0x4b, 0x47, 0x44];

/// The IDAT chunk header of a PNG file.
const IDAT: [u8; 4] = [0x49, 0x44, 0x41, 0x54];

/// Attempts to find the first position of a chunk type within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
/// * `chunk_type` - The type of chunk to find.
///
pub(crate) fn find_chunk_start(path: &str, chunk_type: PngChunkType) -> Option<usize> {
    let Ok(file) = File::open(path) else {
        return None;
    };

    // Create a read-only memory map of the file.
    let mmap = unsafe {
        if let Ok(m) = Mmap::map(&file) {
            m
        } else {
            return None;
        }
    };

    let seq = match chunk_type {
        PngChunkType::Bkgd => &BKGD,
        PngChunkType::Idat => &IDAT,
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
pub(crate) fn generate_bkgd_chunk(data: &[u8]) -> Vec<u8> {
    assert_eq!(
        data.len(),
        6,
        "the bKGD data chunk must have exactly 6 bytes for a 32-bit PNG file"
    );

    // bKGD chunk.
    // See: http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    // The first four bytes will hold the length, which will be updated below.
    let mut chunk = vec![0, 0, 0, 0];
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
pub fn get_chunk_data(data: &[u8]) -> Option<&[u8]> {
    let data_len = get_chunk_length(data)?;

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
pub(crate) fn get_chunk_length(data: &[u8]) -> Option<u32> {
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
pub fn insert_or_replace_bkgd_chunk(path: &str, data: &[u8]) -> Result<()> {
    // bKGD chunk.
    // See: http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html
    // The chunk must be after the PLTE chunk, and before the first IDAT chunk.
    // As we do not create PLTE chunks, we can safely ignore those here.

    let idat = find_chunk_start(path, PngChunkType::Idat);
    if idat.is_none() {
        return Err(Error::ImageMalformed);
    }

    // Generate the entire bKGD the chunk.
    let chunk = generate_bkgd_chunk(data);

    // Does a bKGD chunk already exists within the PNG file?
    // If it does we want to remove it, before replacing it with our own data.
    if find_chunk_start(path, PngChunkType::Bkgd).is_some() && !remove_bkgd_chunk(path) {
        return Err(Error::FileWrite);
    }

    // Splice the chunk data into the image file.
    file_utils::splice_data_into_file(path, idat.unwrap() as u64, &chunk)
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
pub fn read_chunk_raw(path: &str, chunk_type: PngChunkType) -> Option<Vec<u8>> {
    // If we have a chunk present then the index of
    // the header will be returned.
    let start = find_chunk_start(path, chunk_type)?;

    // Create a read-only memory map of the file.
    let Ok(file) = File::open(path) else {
        return None;
    };
    let mmap = unsafe {
        if let Ok(m) = Mmap::map(&file) {
            m
        } else {
            return None;
        }
    };

    // The start of a chunk is always four bytes before the chunk header.
    // The initial four bytes of the chunk give the length of the data
    // portion of the chunk.
    let len_bytes = &mmap[start..start + 4];
    if len_bytes.len() < 4 {
        return None;
    }

    // As there must be at least four bytes available, this
    // unwrap is safe and can't fail.
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

/// Remove a bKGD chunk from within a PNG file.
///
/// # Arguments
///
/// * `path` - The path to the file.
///
pub(crate) fn remove_bkgd_chunk(path: &str) -> bool {
    // Do we have a valid bKGD chunk to remove?
    let Some(chunk) = read_chunk_raw(path, PngChunkType::Bkgd) else {
        return true;
    };

    /*
       Next, we need to read the length of the chunk data.
       For our uses there should always be 6 bytes, but better to be safe here.
       The unwrap is safe here since read_chunk_raw verifies the length of the
         data is sufficient
    */
    let chunk_len = get_chunk_length(&chunk).unwrap();

    // 4 bytes for the length of the chunk's data,
    // 4 bytes for the chunk header,
    // the number of bytes representing the data,
    // 4 more bytes for the CRC checksum.
    let full_len = (8 + chunk_len + 4) as u64;

    // The unwrap is safe here since we know that the chunk must exist.
    let start_index = find_chunk_start(path, PngChunkType::Bkgd).unwrap();

    // Remove the file segment.
    file_utils::remove_file_segment(path, start_index as u64, full_len).is_ok()
}
