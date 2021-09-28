use std::path::PathBuf;

use crate::{
    generate_mnemonic, Key, KeyCreationOutput, KeyError, KeyPair, KeyType, Network, Node, NodeId,
    WalletError,
};

#[derive(Debug, Clone)]
pub struct Wallet {
    root: Option<NodeId>,
    network: Network,
    keys: Vec<Node>,
    path: PathBuf,
}

impl Wallet {
    /// Create a new wallet
    pub fn new(network: Network, path: PathBuf) -> Self {
        Self {
            keys: vec![],
            root: None,
            network,
            path,
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

    /// create a normally derived wallet
    pub fn init(
        &mut self,
        mnemonic: String,
        network: Network,
        compress_public_keys: bool,
    ) -> Result<Self, WalletError> {
        let KeyCreationOutput { mnemonic, key } = self
            .generate_master_key(compress_public_keys)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let master_public_key = key
            .new_public_key()
            .map_err(|e| WalletError::Key(e.to_string()))?;

        let master_key_pair = KeyPair {
            private_key: key.clone(),
            public_key: master_public_key,
            key_type: KeyType::Master,
            index: None,
        };

        let master_node = Node {
            parent: None,
            previous_sibling: None,
            next_sibling: None,
            first_child: None,
            last_child: None,
            key_pair: master_key_pair,
        };

        let hardened_key = key
            .derive_child_private_key(0, crate::ChildKeyType::Hardened)
            .map_err(|e| WalletError::Key(e.to_string()))?;

        todo!()
    }

    /// return a map of the keys in the wallet
    pub fn keys(&self) -> &Vec<Node> {
        &self.keys
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
        for Node { key_pair, .. } in &self.keys {
            let address = key_pair.private_key.address().map_err(|e| {
                KeyError::Other(format!(
                    "Error converting key `{}`: {}",
                    key_pair.private_key.hex(),
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

        let keypair = KeyPair {
            private_key: key.clone(),
            public_key: pubkey,
            key_type: crate::KeyType::Master,
            index: None,
        };

        let node = Node {
            parent: None,
            previous_sibling: None,
            next_sibling: None,
            first_child: None,
            last_child: None,
            key_pair: keypair,
        };

        let index = self.insert(node);
        self.root = Some(index);

        Ok(KeyCreationOutput { mnemonic, key })
    }

    /// insert a keypair node to self.keys
    fn insert(&mut self, node: Node) -> NodeId {
        let next_index = self.keys.len();
        self.keys.push(node);
        NodeId { index: next_index }
    }

    /// get a keypair from self.keys
    fn get(&self, node_id: NodeId) -> Option<Node> {
        self.keys.get(node_id.index).cloned()
    }

    /// write the contents of self.keys to self.path as json
    fn flush(&self) -> Result<(), WalletError> {
        todo!()
    }
}
