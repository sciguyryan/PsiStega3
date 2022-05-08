use std::{fs::File, io::Write};

use crate::{
    error::{Error, Result},
    macros::unwrap_res_or_return,
    utilities::file_utils,
};

use crc32fast::Hasher as Crc32;

#[derive(Debug, Eq, PartialEq)]
pub enum PngChunkType {
    /// Animation control (APNG).
    Actl,
    /// Background colour.
    Bkgd,
    /// Primary chromaticities.
    Chrm,
    /// Frame control (APNG).
    Fctl,
    /// Frame data (APNG).
    Fdat,
    /// Image gamma.
    Gama,
    /// Palette histogram.
    Hist,
    /// Embedded ICC profile.
    Iccp,
    /// Image data.
    Idat,
    /// Image trailer.
    Iend,
    /// Image header.
    Ihdr,
    /// International textual data.
    Itxt,
    /// Palette
    Plte,
    /// Physical dimensions.
    Phys,
    /// Significant bits.
    Sbit,
    /// Suggested palette
    Splt,
    /// Standard RGB color space.
    Srgb,
    /// Textual data.
    Text,
    /// Image last-modification time.
    Time,
    /// Transparency.
    Trns,
    /// Unrecognized chunk type.
    Unknown,
    /// Compressed textual data.
    Ztxt,
}

/// The signature of a PNG file.
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

pub struct PngFile {
    chunks: Vec<PngChunk>,
}

impl PngFile {
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    pub fn open(path: &str) -> Result<PngFile> {
        if !file_utils::path_exists(path) {
            return Err(Error::PathInvalid);
        }

        // Load the entire file into a u8 vector.
        let vec = file_utils::read_file_to_u8_vec(path)?;

        //use std::time::Instant;
        //let now = Instant::now();
        //for i in 0..10 {
        // Parse the PNG file.
        let mut file = PngFile::new();
        if file.parse(&vec).is_err() {
            //return Err(Error::ImageMalformed);
        }
        //}
        //let elapsed = now.elapsed();
        //println!("Elapsed: {:.2?}", elapsed);

        Ok(file)
    }

    pub fn insert_chunk_after(&mut self, chunk: PngChunk, before: PngChunkType) -> bool {
        let index = self.chunks.iter().position(|r| r.chunk_type == before);

        //println!("Chunks = {}", self.chunks.len());

        if let Some(i) = index {
            self.chunks.insert(i + 1, chunk);

            //println!("{:?}", index);
            //println!("Chunks = {}", self.chunks.len());

            true
        } else {
            false
        }
    }

    pub fn parse(&mut self, bytes: &[u8]) -> Result<()> {
        // Does the file start with the PNG signature?
        if !bytes.starts_with(&PNG_SIGNATURE) {
            return Err(Error::ImageMalformed);
        }

        let len = bytes.len();
        let mut pos = PNG_SIGNATURE.len();

        while pos < len {
            // Attempt to read the next chunk of data from the file.
            let chunk = match PngChunk::try_from(&bytes[pos..]) {
                Ok(c) => c,
                Err(e) => return Err(e),
            };

            // Move the index to the start of the next chunk.
            pos += chunk.total_length as usize;

            //println!("chunk type: {:?}", chunk.chunk_type);

            // Add the valid chunk to the chunk list.
            self.chunks.push(chunk);
        }

        Ok(())
    }

    pub fn write_to_file(&self, path: &str) -> bool {
        let mut file = unwrap_res_or_return!(File::create(path), false);

        // First the header must be written to the file.
        let _wb = file.write_all(&PNG_SIGNATURE);

        // Next, we need to write all of the chunks.
        for c in &self.chunks {
            // First, we write the length, in big Endian format.
            let _wb = file.write_all(&c.get_data_len_as_be_bytes());

            // Next, the chunk header.
            let _wb = file.write_all(&c.chunk_type_raw);

            // Next, the chunk data.
            let _wb = file.write_all(&c.data);

            // Finally, the chunk CRC.
            let _wb = file.write_all(&c.hash);
        }

        true
    }
}

impl Default for PngFile {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PngChunk {
    pub chunk_type_raw: Vec<u8>,
    pub chunk_type: PngChunkType,
    pub data: Vec<u8>,
    pub hash: Vec<u8>,
    pub total_length: usize,
}

impl PngChunk {
    pub fn new(chunk_type_raw: &[u8], data: &[u8], hash: &[u8]) -> PngChunk {
        let chunk_type = PngChunk::get_chunk_type_from_slice(chunk_type_raw);
        let total_length = 4 + 4 + data.len() + 4;

        Self {
            chunk_type_raw: chunk_type_raw.to_vec(),
            chunk_type,
            data: data.to_vec(),
            hash: hash.to_vec(),
            total_length,
        }
    }

    pub fn get_data_len_as_be_bytes(&self) -> [u8; 4] {
        (self.data.len() as u32).to_be_bytes()
    }

    pub fn get_data_length(&self) -> usize {
        self.data.len()
    }

    pub fn calculate_and_update_crc(&mut self) {
        let mut hasher = Crc32::new();
        hasher.update(&self.chunk_type_raw);
        hasher.update(&self.data);

        self.hash = hasher.finalize().to_be_bytes().to_vec();
    }

    fn calculate_crc(&self) -> Vec<u8> {
        let mut hasher = Crc32::new();
        hasher.update(&self.chunk_type_raw);
        hasher.update(&self.data);
        hasher.finalize().to_be_bytes().to_vec()
    }

    fn check_crc(&self) -> bool {
        self.calculate_crc() == self.hash
    }

    /// Get the length of a PNG chunk's data segment.
    ///
    /// # Arguments
    ///
    /// * `data` - The contents of the PNG chunk.
    ///
    fn get_chunk_length(data: &[u8]) -> Option<u32> {
        if data.len() < 4 {
            return None;
        }

        // The length of the chunk's data segment is given by the first four
        // bytes of the chunk. The unwrap is safe here since we have verified
        // the data length above.
        let chunk_len_arr = <[u8; 4]>::try_from(&data[..4]).unwrap();
        Some(u32::from_be_bytes(chunk_len_arr))
    }

    fn get_chunk_type_from_slice(data: &[u8]) -> PngChunkType {
        let chunk_type_bytes = <[u8; 4]>::try_from(data).unwrap();
        let chunk_type = match &chunk_type_bytes {
            b"acTL" => PngChunkType::Actl,
            b"bKGD" => PngChunkType::Bkgd,
            b"cHRM" => PngChunkType::Chrm,
            b"fcTL" => PngChunkType::Fctl,
            b"fdAT" => PngChunkType::Fdat,
            b"gAMA" => PngChunkType::Gama,
            b"hIST" => PngChunkType::Hist,
            b"iCCP" => PngChunkType::Iccp,
            b"IDAT" => PngChunkType::Idat,
            b"IEND" => PngChunkType::Iend,
            b"IHDR" => PngChunkType::Ihdr,
            b"iTXt" => PngChunkType::Itxt,
            b"PLTE" => PngChunkType::Plte,
            b"pHYs" => PngChunkType::Phys,
            b"sBIT" => PngChunkType::Sbit,
            b"sPLT" => PngChunkType::Splt,
            b"sRGB" => PngChunkType::Srgb,
            b"tEXt" => PngChunkType::Text,
            b"tIME" => PngChunkType::Time,
            b"tRNS" => PngChunkType::Trns,
            b"zTXt" => PngChunkType::Ztxt,
            _ => {
                println!(
                    "Unknown chunk type: {}",
                    String::from_utf8_lossy(&chunk_type_bytes)
                );
                PngChunkType::Unknown
            }
        };

        chunk_type
    }
}

impl TryFrom<&[u8]> for PngChunk {
    type Error = crate::error::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        // A chunk will always start with 4 bytes that specify the length
        // of the data segment of the chunk.
        let chunk_len = match PngChunk::get_chunk_length(bytes) {
            Some(len) => len as usize,
            None => return Err(Error::ImageMalformed),
        };

        // Four bytes for the length of the chunk's data.
        // Four bytes for the chunk type header.
        // X bytes will for the data chunk's data.
        // Four bytes for the CRC32 checksum of the chunk.
        let total_length = 4 + 4 + chunk_len + 4;

        // If there are insufficient bytes to hold the chunk data,
        // then the image is malformed and we can't continue to parse
        // the file.
        if total_length > bytes.len() {
            return Err(Error::ImageMalformed);
        }

        // The chunk type header will be found in the next four bytes.
        let chunk_type_bytes = &bytes[4..8];

        // The next segment contains the data for the chunk.
        // This extends from 8 bytes after the start of the chunk
        // to 4 bytes before the end of the chunk.
        let data_end = 8 + chunk_len;
        let chunk_data = &bytes[8..data_end];

        // The final 4 bytes will give the checksum of the chunk.
        let chunk_crc = &bytes[data_end..(data_end + 4)];

        // Create the chunk struct from the extracted data.
        let chunk = PngChunk::new(chunk_type_bytes, chunk_data, chunk_crc);

        // Now that all of the data has been processed, we need to check
        // whether the calculated hash matches the hash read from the data.
        if !chunk.check_crc() {
            // TODO: we could  potentially simply skip this chunk,
            // TODO: rather than terminating the parsing completely.
            return Err(Error::ImageMalformed);
        }

        Ok(chunk)
    }
}
