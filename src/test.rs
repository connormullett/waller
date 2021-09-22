#[cfg(test)]
mod test {

    use crate::{Key, KeyOptions};

    #[test]
    pub fn test_new_key() {
        let options = KeyOptions::Seed("foo bar");
        let network = crate::Network::Mainnet;
        let key = Key::new(options, network, false);

        let wif = key.to_wif();
        let key_from_wif = Key::from_wif(wif).unwrap();

        assert_eq!(key_from_wif.bytes(), key.bytes())
    }
}
