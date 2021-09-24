use std::fmt::Display;

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

/// Generic Error type for decoding/encoding
/// from import formats and other errors
#[derive(Debug, Clone)]
pub enum KeyError {
    Decode,
    InvalidFormat,
    ChecksumMismatch,
    InvalidNetworkByte,
    IndexOutOfRange,
    TooLong(String),
    BadMnemonicPhrase(String),
    Other(String),
}

impl Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            KeyError::Decode => "Error decoding key".to_string(),
            KeyError::InvalidFormat => "Key was not in a valid format".to_string(),
            KeyError::ChecksumMismatch => "Checksum verification failed".to_string(),
            KeyError::InvalidNetworkByte => "Network byte was invalid".to_string(),
            KeyError::TooLong(error) => format!("Key was too long in length: {}", error),
            KeyError::BadMnemonicPhrase(error) => {
                format!("Mnemonic prhase was incorrect: {}", error)
            }
            KeyError::Other(error) => format!("an error occured: {}", error),
            KeyError::IndexOutOfRange => {
                "The index used for child key derivation was too large".to_string()
            }
        };
        write!(f, "{}", string)
    }
}

pub enum ChildKeyType {
    Normal,
    Hardened,
}
