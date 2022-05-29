use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub enum TransactionVersion {
    One,
}

/// a transaction in Raw format
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// transaction version number. currently either 1 or 2
    version: TransactionVersion,
    /// the inputs to the transaction
    tx_in: Vec<TransactionInput>,
    /// vector of transaction outputs
    tx_out: Vec<TransactionOutput>,
    /// a timestamp or block number
    lock_time: u128,
}

impl RawTransaction {
    pub fn new(
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: Option<u128>,
    ) -> Self {
        match lock_time {
            Some(time) => Self {
                version: TransactionVersion::One,
                tx_in: inputs,
                tx_out: outputs,
                lock_time: time,
            },
            None => {
                let start = SystemTime::now();
                Self {
                    version: TransactionVersion::One,
                    tx_in: inputs,
                    tx_out: outputs,
                    lock_time: start
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards")
                        .as_millis(),
                }
            }
        }
    }

    pub fn tx_id(&self) -> String {
        // hash all tx data with sha256 twice
        todo!()
    }

    pub fn version(&self) -> TransactionVersion {
        self.version.clone()
    }

    pub fn inputs(&self) -> Vec<TransactionInput> {
        self.tx_in.clone()
    }

    pub fn outputs(&self) -> Vec<TransactionOutput> {
        self.tx_out.clone()
    }

    /// The amount of inputs in the transaction
    pub fn tx_in_count(&self) -> usize {
        self.tx_in.len()
    }

    /// The amount of outputs in the transaction
    pub fn tx_out_count(&self) -> usize {
        self.tx_out.len()
    }

    pub fn lock_time(&self) -> u128 {
        self.lock_time
    }
}

#[derive(Debug, Clone)]
pub struct TransactionInput {
    /// previous output being spent
    previous_output: OutPoint,
    /// number of bytes in sig script. Max is 10_000
    script_bytes: usize,
    /// a script-language script with satisfies the conditions
    /// placed in the outpoints pubkey script
    /// should only contain data pushes
    signature_script: String,
    /// sequence number. Default is 0xffffffff
    sequence: u32,
}

/// a tx can have multiple outputs so the Outpoint
/// includes a txid and an output index to refer
/// to a specific output
#[derive(Debug, Clone)]
pub struct OutPoint {
    /// the TXID of the tx holding the output to spend
    hash: String,
    /// output index number of the specific output
    /// to spend from the transaction
    /// the first output is 0x00000000
    index: i32,
}

/// each output spends a certain number of sats
/// placing them under control of anyone who can
/// satisfy the provided pubkey script
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    /// number of satoshis to spend
    value: i64,
    /// number of bytes in the pubkey script. max is 10_000 bytes
    pk_script_bytes: usize,
    /// defines the conditions which must be satisfied to spend this output
    pk_script: String,
}
