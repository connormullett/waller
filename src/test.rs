#[cfg(test)]
mod test {

    use crate::{generate_mnemonic, Key, Network};

    #[test]
    pub fn test_new_key() {
        let mnemonic = String::from(
            "fancy lemon deliver stock castle eye answer palm nerve exchange sibling asset",
        );
        let network = Network::Mainnet;

        let key = Key::new(mnemonic, network, false).unwrap();

        let wif = key.to_wif();
        let key_from_wif = Key::from_wif(wif).unwrap();

        assert_eq!(key_from_wif.bytes(), key.bytes())
    }

    #[test]
    pub fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic();
        println!("{}", mnemonic);
    }
}
