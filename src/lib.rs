mod test;

mod types;
mod utils;
mod wallet;

use bip39::{Language, Mnemonic};
pub use types::*;
pub use utils::*;
pub use wallet::*;

#[derive(Debug)]
pub enum MnemonicError {
    Generation(String),
}

pub fn generate_mnemonic() -> Result<String, MnemonicError> {
    let entropy = get_random_bytes(16);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| MnemonicError::Generation(e.to_string()))?;
    Ok(mnemonic.to_string())
}
