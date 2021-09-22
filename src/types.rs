/// options for key generation
#[derive(Debug, Clone)]
pub enum KeyOptions<'a> {
    Seed(&'a str),
    Random,
}

/// bitcoin networks
#[derive(Debug, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}
