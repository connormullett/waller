mod test;

mod types;
mod utils;
mod wallet;

use bip0039::Count;
use bip0039::Mnemonic;
pub use types::*;
pub use utils::*;
pub use wallet::*;

#[derive(Debug)]
pub enum MnemonicError {
    Generation(String),
}

pub fn generate_mnemonic() -> String {
    let mnemonic = Mnemonic::generate(Count::Words12);
    mnemonic.phrase().to_string()
}
