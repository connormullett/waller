use bip0039::Mnemonic;
use num_bigint::BigInt;
use secp256k1::{constants::CURVE_ORDER, PublicKey, Secp256k1, SecretKey};

use crate::{
    hmac_sha512_hash, ripemd160_hash, sha256_hash, sha256_hash_twice, sha512_hash, ChildKeyType,
    KeyError, Network,
};

/// a bitcoin private key
#[derive(Debug, Clone)]
pub struct Key {
    bytes: Vec<u8>,
    network: Network,
    compress_public_keys: bool,
    chain_code: Vec<u8>,
}

impl Key {
    /// Create a new recoverable key from a BIP39 conforming mnemonic phrase
    pub fn new(
        mnemonic: String,
        network: Network,
        compress_public_keys: bool,
    ) -> Result<Self, KeyError> {
        let mnemonic = Mnemonic::from_phrase(mnemonic).unwrap();
        let seed = mnemonic.to_seed("");
        let mut hash = sha512_hash(&seed.to_vec());

        let chain_code = hash.split_off(32);

        let secret_key =
            SecretKey::from_slice(&hash).map_err(|e| KeyError::TooLong(e.to_string()))?;

        Ok(Self {
            bytes: secret_key.as_ref().to_vec(),
            network,
            compress_public_keys,
            chain_code,
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

        let mnemonic = Mnemonic::from_entropy(decoded.clone()).map_err(|_| KeyError::Decode)?;
        let seed = mnemonic.to_seed("");
        let mut hash = sha512_hash(&seed.to_vec());

        let chain_code = hash.split_off(32);

        Ok(Self {
            bytes: decoded,
            network,
            compress_public_keys,
            chain_code,
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

    /// derive a public key from this private key
    pub fn new_public_key(&self) -> Result<Vec<u8>, KeyError> {
        let secret =
            SecretKey::from_slice(self.bytes()).map_err(|e| KeyError::Other(e.to_string()))?;

        let key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        let key = match self.compress_public_keys {
            true => key.serialize().to_vec(),
            false => key.serialize_uncompressed().to_vec(),
        };

        Ok(key)
    }

    /// generate a base58 encoded address from this key
    pub fn address(&self) -> Result<String, KeyError> {
        let pubkey = self.new_public_key()?;
        let f_hash = sha256_hash(&pubkey);
        let mut encrypted_pubkey = ripemd160_hash(&f_hash);

        match self.network {
            Network::Mainnet => encrypted_pubkey.insert(0, 0x00),
            Network::Testnet => encrypted_pubkey.insert(0, 0x6f),
        }

        let mut checksum = sha256_hash_twice(&encrypted_pubkey);

        encrypted_pubkey.append(&mut checksum);

        Ok(bs58::encode(&encrypted_pubkey).into_string())
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

    /// return the extended private key. This is the private key
    /// with the chain code appended to the end. Used for deriving
    /// child private keys in HD wallets
    pub fn extended_private_key(&self) -> Vec<u8> {
        let mut bytes = self.bytes.clone();

        bytes.append(&mut self.chain_code.clone());
        bytes
    }

    /// return the extended public key. This is the public key
    /// with the chain code appended to the end. Used for deriving
    /// child public keys in HD wallets
    pub fn extended_public_key(&self) -> Result<Vec<u8>, KeyError> {
        let mut pubkey = self.new_public_key()?;
        pubkey.append(&mut self.chain_code.clone());
        Ok(pubkey)
    }

    /// Create a child private key
    /// can be either normal or hardened
    pub fn derive_child_private_key(
        &self,
        index: usize,
        key_type: ChildKeyType,
    ) -> Result<Key, KeyError> {
        match key_type {
            ChildKeyType::Normal if index > 2147483647 => return Err(KeyError::IndexOutOfRange),
            ChildKeyType::Hardened if index < 2147483647 || index > 4294967295 => {
                return Err(KeyError::IndexOutOfRange)
            }
            _ => {}
        }

        let mut pubkey = self.new_public_key()?;
        pubkey.append(&mut index.to_le_bytes().to_vec());

        let mut hash = hmac_sha512_hash(&pubkey, &self.chain_code);

        let chain_code = hash.split_off(32);

        let curve_order = BigInt::from_signed_bytes_le(&CURVE_ORDER);
        let hash_int = BigInt::from_signed_bytes_le(&hash);
        let prev_key = BigInt::from_signed_bytes_le(&self.bytes());

        let key = (hash_int + prev_key) % curve_order;
        let private_key = key.to_signed_bytes_le();

        Ok(Key {
            bytes: private_key,
            network: self.network,
            chain_code,
            compress_public_keys: self.compress_public_keys,
        })
    }

    /// Create normal child public key
    pub fn derive_normal_child_public_key(&self) -> Vec<u8> {
        todo!()
    }
}
