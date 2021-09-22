use bip0039::Mnemonic;
use secp256k1::SecretKey;

use crate::{sha256_hash, sha256_hash_twice, Network};

/// Generic Error type for decoding/encoding
/// from import formats and other errors
#[derive(Debug, Clone)]
pub enum KeyError {
    Decode,
    InvalidFormat,
    ChecksumMismatch,
    InvalidNetworkByte,
    TooLong(String),
    BadMnemonicPhrase(String),
}

/// a bitcoin private key
#[derive(Debug, Clone)]
pub struct Key {
    bytes: Vec<u8>,
    network: Network,
    compress_public_keys: bool,
}

impl Key {
    /// Create a new recoverable key from a BIP39 conforming mnemonic phrase
    pub fn new(
        mnemonic: String,
        network: Network,
        compress_public_keys: bool,
    ) -> Result<Self, KeyError> {
        let mnemonic = Mnemonic::from_phrase(mnemonic).unwrap();

        let hash = sha256_hash(&mnemonic.to_seed("").to_vec());
        let secret_key =
            SecretKey::from_slice(&hash).map_err(|e| KeyError::TooLong(e.to_string()))?;

        Ok(Self {
            bytes: secret_key.as_ref().to_vec(),
            network,
            compress_public_keys,
        })
    }

    /// create a new key given a wallet import format string
    pub fn from_wif(input: String) -> Result<Self, KeyError> {
        let mut decoded = bs58::decode(input)
            .into_vec()
            .map_err(|_| KeyError::Decode)?;
        let checksum = decoded.split_off(decoded.len().saturating_sub(4));
        let hash_result = sha256_hash_twice(&decoded);

        if hash_result[..4] != checksum {
            return Err(KeyError::ChecksumMismatch);
        }

        let network = match decoded.remove(0) {
            0x80 => Network::Mainnet,
            0xef => Network::Testnet,
            _ => return Err(KeyError::InvalidNetworkByte),
        };

        let last_byte = match decoded.last() {
            Some(byte) => byte,
            None => return Err(KeyError::InvalidFormat),
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

    /// return the wif representation of the key
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

    /// return a reference to the underlying key
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// return the network associated with this key
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// check if public key compression is enabled
    pub fn compress_public_keys(&self) -> bool {
        self.compress_public_keys
    }

    /// get a hex encoded string of the underlying key
    pub fn hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}
