use crate::Key;

/// bitcoin networks
#[derive(Debug, Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone)]
pub struct KeyCreationOutput {
    pub mnemonic: String,
    pub key: Key,
}
