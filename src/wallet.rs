use crate::{generate_mnemonic, Key, KeyCreationOutput, KeyError, Network};

pub struct Wallet {
    keys: Vec<Key>,
    network: Network,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(network: Network) -> Self {
        Self {
            keys: vec![],
            network,
        }
    }

    /// return a vector of the keys in the wallet
    pub fn keys(&self) -> &Vec<Key> {
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
        for key in &self.keys {
            let address = key.address().map_err(|e| {
                KeyError::Other(format!(
                    "Error converting key `{}`: {}",
                    key.hex(),
                    e.to_string()
                ))
            })?;
            output.push(address);
        }
        Ok(output)
    }

    /// create a new key from a new mnemonic
    /// and add it to the wallet. returns
    /// the mnemonic used and the key as a
    /// KeyCreationOutput object
    pub fn generate_key(
        &mut self,
        compress_public_keys: bool,
    ) -> Result<KeyCreationOutput, KeyError> {
        let mnemonic = generate_mnemonic();
        let key = Key::new(mnemonic.clone(), self.network, compress_public_keys)?;
        self.keys.push(key.clone());

        Ok(KeyCreationOutput { mnemonic, key })
    }
}
