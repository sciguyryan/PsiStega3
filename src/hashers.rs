use argon2::{Argon2, Version};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::io::prelude::*;

use crate::error::{Error, Result};

pub struct Hashers {}

impl Hashers {
    pub fn sha3_512_file(path: &str) -> Vec<u8> {
        let mut hasher = Sha3_512::new();

        // The file will automatically be closed when it goes out of scope.
        let mut f = std::fs::File::open(path).unwrap();
        let mut buffer = [0u8; 16384];

        loop {
            let n = f.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        hasher.finalize().to_vec()
    }

    pub fn sha3_256_string(str: &str) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&str);
        hasher.finalize().to_vec()
    }

    pub fn argon2_string(str: &str, salt: [u8; 12], m_cost: u32, p_cost: u32, t_cost: u32, version: argon2::Version) -> Result<[u8; 128]> {
        let mut builder = argon2::ParamsBuilder::new();

        if builder.m_cost(m_cost).is_err() {
            return Err(Error::Argon2InvalidParams);
        };

        if builder.p_cost(p_cost).is_err() {
            return Err(Error::Argon2InvalidParams);
        };

        if builder.t_cost(t_cost).is_err() {
            return Err(Error::Argon2InvalidParams);
        };

        // The parameter builder will fail if any of the params are incorrect, this unwrap should be safe as a result.
        let params = builder.params().unwrap();

        // Convert the string to a byte array.
        let str_bytes = str.as_bytes();

        // Construct the hasher.
        let hasher =  Argon2::new(argon2::Algorithm::Argon2id, version, params);

        let mut key_bytes = [0u8; 128];
        if hasher.hash_password_into(str_bytes, &salt, &mut key_bytes).is_err() {
            return Err(Error::Argon2NoHash);
        }

        Ok(key_bytes)
    }
}

pub struct Argon2Parameters {
    t_cost: u32,
    p_cost: u32,
    m_cost: u32,
    version: argon2::Version
}

impl Argon2Parameters {
    pub fn new(t_cost: u32, p_cost: u32, m_cost: u32, version: argon2::Version) -> Self {
        Self {
            t_cost,
            p_cost,
            m_cost,
            version
        }
    }
}
