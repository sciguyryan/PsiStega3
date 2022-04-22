use argon2::Argon2;
use sha3::{Digest, Sha3_256, Sha3_512};
use std::io::prelude::*;

use crate::error::{Error, Result};

pub struct Hashers {}

impl Hashers {
    #[allow(dead_code)]
    pub fn sha3_256_file(path: &str) -> Result<Vec<u8>> {
        let mut hasher = Sha3_256::new();

        // The file will automatically be closed when it goes out of scope.
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Err(Error::FileHashingError);
            }
        };
        let mut buffer = [0u8; 16384];

        // Loop until we have read the entire file (in chunks).
        loop {
            let n = file.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(hasher.finalize().to_vec())
    }

    pub fn sha3_512_file(path: &str) -> Result<Vec<u8>> {
        let mut hasher = Sha3_512::new();

        // The file will automatically be closed when it goes out of scope.
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => {
                return Err(Error::FileHashingError);
            }
        };
        let mut buffer = [0u8; 16384];

        // Loop until we have read the entire file (in chunks).
        loop {
            let n = file.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(hasher.finalize().to_vec())
    }

    pub fn sha3_256_string(str: &str) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&str);
        hasher.finalize().to_vec()
    }

    pub fn argon2_string(
        str: &str,
        salt: [u8; 12],
        m_cost: u32,
        p_cost: u32,
        t_cost: u32,
        version: argon2::Version,
    ) -> Result<[u8; 128]> {
        let mut builder = argon2::ParamsBuilder::new();

        if builder.m_cost(m_cost).is_err()
            || builder.p_cost(p_cost).is_err()
            || builder.t_cost(t_cost).is_err()
        {
            return Err(Error::Argon2InvalidParams);
        };

        // This method return an error condition if any of supplied
        // parameters are incorrect prior to this statement.
        // This unwrap should be safe as a result.
        let params = builder.params().unwrap();

        // Construct the hasher.
        let hasher = Argon2::new(argon2::Algorithm::Argon2id, version, params);

        // Nom!
        let mut key_bytes = [0u8; 128];
        if hasher
            .hash_password_into(str.as_bytes(), &salt, &mut key_bytes)
            .is_err()
        {
            return Err(Error::Argon2NoHash);
        }

        Ok(key_bytes)
    }
}
