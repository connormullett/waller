use std::{fs, path::PathBuf};

use libarena::{Arena, Node};
use serde::{Deserialize, Serialize};

use crate::{
    generate_mnemonic, ChildKeyType, Key, KeyCreationOutput, KeyError, KeyPair, KeyType, Network,
    Transaction, TransactionInput, TransactionOutput, TransactionType, WalletError,
};

/// A bitcoin HD wallet
/// keys are stored in a graph using arena allocation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Wallet {
    network: Network,
    path: PathBuf,
    next_hardened_index: usize,
    next_normal_index: usize,
    compress_public_keys: bool,
    arena: Arena<KeyPair, String>,
    encrypted: bool,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(
        network: Network,
        path: PathBuf,
        compress_public_keys: bool,
        encrypted: bool,
    ) -> Self {
        Self {
            arena: Arena::new(),
            network,
            path,
            next_hardened_index: 2147483647,
            next_normal_index: 1,
            compress_public_keys,
            encrypted,
        }
    }

    /// Restore an HD wallet, all keys lost can be recovered
    /// from the mnemonic seed used to build it, however generating
    /// every key can be very expensive computationally
    pub fn restore(
        mnemonic: String,
        network: Network,
        compress_public_keys: bool,
        data_path: PathBuf,
        encrypted: bool,
    ) -> Result<Self, WalletError> {
        let key = Key::new(mnemonic.clone(), network, compress_public_keys)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let mut wallet = Wallet::new(network, data_path, compress_public_keys, encrypted);

        let _ = wallet.create_key_chain(key, mnemonic)?;

        Ok(wallet)
    }

    /// Create a wallet from an existing backedup json wallet file
    /// This is a serde serialized string of the [Wallet] type
    pub fn from_wallet_file(path: PathBuf) -> Result<Self, WalletError> {
        let data = fs::read_to_string(path)
            .map_err(|e| WalletError::Read(format!("Failed to read file: {}", e.to_string())))?;

        let imports = serde_json::from_str(&data).map_err(|e| {
            WalletError::Read(format!("Failed to deserialize data: {}", e.to_string()))
        })?;

        Ok(imports)
    }

    /// initialize a new wallet
    /// on success, returns the mnemonic used to create the wallet
    pub fn init(&mut self) -> Result<String, WalletError> {
        let KeyCreationOutput { mnemonic, key } =
            self.generate_master_key(self.compress_public_keys)?;

        self.create_key_chain(key, mnemonic)
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

    /// change the path to a new location
    pub fn set_path(&mut self, path: PathBuf) -> Result<(), WalletError> {
        self.path = path;
        self.flush()
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

    /// Change and set the use of encryption or none
    pub fn set_encryption(&mut self, encrypted: bool) {
        self.encrypted = encrypted;
    }

    /// create the master key of the wallet, all keys will be derived from this key
    /// returns the mnemonic that was used to generate this key and the key itself
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

    /// Create a new transaction using a keypair
    /// supported transaction types are P2PKH and P2SH
    pub fn new_transaction(
        &self,
        tx_type: TransactionType,
        _key: KeyPair,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: Option<u128>,
    ) -> Transaction {
        Transaction::new(tx_type, inputs, outputs, lock_time);
        todo!("create pk and sig scripts")
    }

    fn create_key_chain(&mut self, key: Key, mnemonic: String) -> Result<String, WalletError> {
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
    /// TODO: key ordering, encryption
    fn flush(&self) -> Result<(), WalletError> {
        let json = serde_json::to_string_pretty(&self.path)
            .map_err(|e| WalletError::Write(e.to_string()))?;

        match self.encrypted {
            false => {
                fs::write(&self.path, json)
                    .map_err(|e| WalletError::Write(format!("Write Error: {}", e.to_string())))?;
                Ok(())
            }
            true => {
                todo!();
            }
        }
    }
}
