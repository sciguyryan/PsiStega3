pub struct FileAttempts {
    hash: Vec<u8>,
    attempts: u8,
}

impl FileAttempts {
    pub fn new(hash: Vec<u8>, attempts: u8) -> Self {
        Self { hash, attempts }
    }
}
