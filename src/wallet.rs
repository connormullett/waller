use std::{collections::HashMap, path::PathBuf};

use crate::{generate_mnemonic, HDKeyPair, Key, KeyCreationOutput, KeyError, Network};

pub struct Wallet {
    keys: HashMap<String, HDKeyPair>,
    network: Network,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(network: Network) -> Self {
        Self {
            keys: HashMap::new(),
            network,
        }
    }

    /// Restore an HD wallet, all keys lost can be recovered
    /// from the mnemonic seed used to build it, however generating
    /// every key can be very expensive computationally
    pub fn restore(_mnemonic: String, _network: Network) -> Self {
        todo!()
    }

    /// Create a wallet from an existing backedup wallet file
    pub fn from_wallet_file(_path: PathBuf) -> Self {
        todo!()
    }

    /// return a map of the keys in the wallet
    pub fn keys(&self) -> &HashMap<String, HDKeyPair> {
        &self.keys
    }

    /// return a reference to the network this
    /// wallet is associated with
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// returns a vec of addresses of all keys in the wallet
    /// if an error occurs, the key that failed is within the error
    pub fn addresses(&self) -> Result<Vec<String>, KeyError> {
        let mut output = vec![];
        for (_, key) in &self.keys {
            let address = key.private_key.address().map_err(|e| {
                KeyError::Other(format!(
                    "Error converting key `{}`: {}",
                    key.private_key.hex(),
                    e.to_string()
                ))
            })?;
            output.push(address);
        }
        Ok(output)
    }

    pub fn generate_master_key(
        &mut self,
        compress_public_keys: bool,
    ) -> Result<KeyCreationOutput, KeyError> {
        let mnemonic = generate_mnemonic();
        let key = Key::new(mnemonic.clone(), self.network, compress_public_keys)?;
        let pubkey = key.new_public_key()?;

        let keypair = HDKeyPair {
            private_key: key.clone(),
            public_key: pubkey,
            key_type: crate::KeyType::Master,
            index: None,
        };

        let path = String::from("m");

        self.keys.insert(path, keypair);

        Ok(KeyCreationOutput { mnemonic, key })
    }
}
