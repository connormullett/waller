use std::path::PathBuf;

use libarena::{Arena, Node};

use crate::{
    generate_mnemonic, ChildKeyType, Key, KeyCreationOutput, KeyError, KeyPair, KeyType, Network,
    WalletError,
};

#[derive(Debug, Clone)]
pub struct Wallet {
    network: Network,
    path: PathBuf,
    next_hardened_index: usize,
    next_normal_index: usize,
    compress_public_keys: bool,
    arena: Arena<KeyPair, String>,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(network: Network, path: PathBuf, compress_public_keys: bool) -> Self {
        Self {
            arena: Arena::new(),
            network,
            path,
            next_hardened_index: 2147483647,
            next_normal_index: 1,
            compress_public_keys,
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

    /// initialize a new wallet
    /// on success, returns the mnemonic used to create the wallet
    pub fn init(&mut self) -> Result<String, WalletError> {
        let KeyCreationOutput { mnemonic, key } =
            self.generate_master_key(self.compress_public_keys)?;

        let hardened_key = key
            .derive_child_private_key(self.next_hardened_index, ChildKeyType::Hardened)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let hardened_key_pair = KeyPair {
            private_key: hardened_key.clone(),
            public_key: hardened_key
                .new_public_key()
                .map_err(|e| WalletError::Key(e.to_string()))?,
            key_type: KeyType::Hardened,
            index: Some(self.next_hardened_index),
        };

        self.next_hardened_index += 1;

        let hardened_index = self.insert(hardened_key_pair.clone(), self.arena.root())?;

        let child_key = hardened_key
            .derive_child_private_key(self.next_normal_index, ChildKeyType::Normal)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let child_key_pair = KeyPair {
            private_key: child_key.clone(),
            public_key: child_key
                .new_public_key()
                .map_err(|e| WalletError::Key(e.to_string()))?,
            key_type: KeyType::Normal,
            index: Some(self.next_normal_index),
        };

        self.next_normal_index += 1;

        let _ = self.insert(child_key_pair, Some(hardened_index));

        let _ = self.flush();

        Ok(mnemonic)
    }

    /// return a list of keys in the wallet
    pub fn keys(&self) -> &Vec<Node<KeyPair, String>> {
        &self.arena.nodes()
    }

    /// return a reference to the network this
    /// wallet is associated with
    pub fn network(&self) -> &Network {
        &self.network
    }

    /// get the path where keys are being saved to disk
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn set_path(&mut self, path: PathBuf) -> Result<(), WalletError> {
        self.path = path;
        Ok(())
    }

    /// returns a vec of addresses of all keys in the wallet
    /// if an error occurs, the key that failed is within the error
    pub fn addresses(&self) -> Result<Vec<String>, KeyError> {
        let mut output = vec![];
        for Node { data, .. } in self.arena.nodes() {
            let address = data.private_key.address().map_err(|e| {
                KeyError::Other(format!(
                    "Error converting key `{}`: {}",
                    data.private_key.hex(),
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
    ) -> Result<KeyCreationOutput, WalletError> {
        let mnemonic = generate_mnemonic();
        let key = Key::new(mnemonic.clone(), self.network, compress_public_keys)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let pubkey = key
            .new_public_key()
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let keypair = KeyPair {
            private_key: key.clone(),
            public_key: pubkey,
            key_type: crate::KeyType::Master,
            index: None,
        };

        let index = self.insert(keypair, None)?;
        self.arena.set_root(Some(index));

        Ok(KeyCreationOutput { mnemonic, key })
    }

    /// insert a keypair node to self.keys
    fn insert(&mut self, keys: KeyPair, parent: Option<usize>) -> Result<usize, WalletError> {
        Ok(self.arena.insert(
            keys.clone(),
            keys.private_key
                .address()
                .map_err(|e| WalletError::Key(e.to_string()))?,
            parent,
        ))
    }

    /// get a keypair by its internal node id
    fn get(&self, index: usize) -> Option<KeyPair> {
        self.arena.get_inner(index).cloned()
    }

    /// get a key in the wallet by an address
    pub fn get_address(&self, address: String) -> Option<Key> {
        if let Some(id) = self.arena.root().clone() {
            match self.get(id) {
                Some(node) => {
                    // check root
                    let key = node.clone().private_key;
                    let node_address = key.address();

                    if node_address.is_err() {
                        return None;
                    }

                    let node_address = node_address.unwrap();

                    // root is the key
                    if address == node_address {
                        return Some(key);
                    }

                    // recursively check node's children from first child to last child
                    let _current_node = node.clone();
                    loop {}
                }
                None => return None,
            }
        } else {
            return None;
        }
    }

    /// write the contents of self.keys to self.path as json
    fn flush(&self) -> Result<(), WalletError> {
        todo!()
    }
}
