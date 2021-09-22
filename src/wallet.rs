use secp256k1::SecretKey;

use crate::{get_random_bytes, sha256_hash_twice, KeyOptions, Network};

#[derive(Debug)]
pub enum Error {
    Decode,
    InvalidFormat,
    ChecksumMismatch,
    InvalidNetworkByte,
}

pub struct Key {
    bytes: Vec<u8>,
    network: Network,
    compress_public_keys: bool,
}

impl Key {
    pub fn new(options: KeyOptions, network: Network, compress_public_keys: bool) -> Self {
        let bytes = match options {
            KeyOptions::Seed(seed) => {
                let bytes = &mut [0u8; 32];
                for (place, data) in bytes.iter_mut().zip(seed.as_bytes().iter()) {
                    *place = *data
                }
                bytes.to_vec()
            }
            KeyOptions::Random => get_random_bytes(256),
        };

        let secret_key =
            SecretKey::from_slice(bytes.as_slice()).expect("32 bytes, within curve order");

        Self {
            bytes: secret_key.as_ref().to_vec(),
            network,
            compress_public_keys,
        }
    }

    pub fn from_wif(input: String) -> Result<Self, Error> {
        let mut decoded = bs58::decode(input).into_vec().map_err(|_| Error::Decode)?;
        let checksum = decoded.split_off(decoded.len().saturating_sub(4));
        let hash_result = sha256_hash_twice(&decoded);

        if hash_result[..4] != checksum {
            return Err(Error::ChecksumMismatch);
        }

        let network = match decoded.remove(0) {
            0x80 => Network::Mainnet,
            0xef => Network::Testnet,
            _ => return Err(Error::InvalidNetworkByte),
        };

        let last_byte = match decoded.last() {
            Some(byte) => byte,
            None => return Err(Error::InvalidFormat),
        };

        let compress_public_keys = if decoded.len() > 32 && *last_byte == 0x01 {
            decoded.pop();
            true
        } else {
            false
        };

        Ok(Self {
            bytes: decoded,
            network,
            compress_public_keys,
        })
    }

    pub fn to_wif(&self) -> String {
        let mut key = self.bytes.clone();

        match self.network {
            Network::Mainnet => key.insert(0, 0x80),
            Network::Testnet => key.insert(0, 0xef),
        }

        if self.compress_public_keys {
            key.push(0x01);
        }

        let hash = sha256_hash_twice(&key);

        let checksum = &hash[..4];

        key.append(&mut checksum.to_vec());

        bs58::encode(key).into_string()
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn network(&self) -> &Network {
        &self.network
    }

    pub fn compress_public_keys(&self) -> bool {
        self.compress_public_keys
    }

    pub fn hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}
