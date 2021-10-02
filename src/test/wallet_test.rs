#![allow(unused_imports)]

use std::path::PathBuf;

use crate::{Network, Wallet};

#[test]
pub fn test_wallet_init() {
    let mut wallet = Wallet::new(Network::Mainnet, PathBuf::from("/tmp"), false);

    let mnemonic = wallet.init().unwrap();

    println!("mnemonic :: {}", mnemonic);
    println!("addresses\n{:#?}", wallet.addresses().unwrap());
}
