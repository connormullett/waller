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

    pub fn get_input(&self, index: usize) -> Option<&TransactionInput> {
        self.tx_in.get(index)
    }

    pub fn get_output(&self, index: usize) -> Option<&TransactionOutput> {
        self.tx_out.get(index)
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
    /// The script to unlock the previous output to be used
    /// as an input in this transaction
    /// to solve this script, the owner of the pub key
    /// needs to provide the original pub key + a valid
    /// signature for it
    /// this looks like <sig><pubkey> + pubkey script + OP_CHECKSIG
    signature_script: String,
}

impl TransactionInput {
    pub fn new(output: OutPoint, signature_script: String) -> Self {
        Self {
            previous_output: output,
            signature_script,
        }
    }

    pub fn script_bytes(&self) -> usize {
        self.signature_script.as_bytes().len()
    }

    pub fn previous_output(&self) -> &OutPoint {
        &self.previous_output
    }
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

impl OutPoint {
    pub fn new(tx_id: String, index: i32) -> Self {
        Self { hash: tx_id, index }
    }

    pub fn hash(&self) -> String {
        self.hash.clone()
    }

    pub fn index(&self) -> i32 {
        self.index
    }
}

/// each output spends a certain number of sats
/// placing them under control of anyone who can
/// satisfy the provided pubkey script
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    /// number of satoshis to spend
    value: i64,
    /// defines the conditions which must be satisfied to spend this output
    pk_script: String,
}

impl TransactionOutput {
    pub fn pubkey_script() {
        // OP_DUP OP_HASH160 <pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
        todo!()
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn script_bytes(&self) -> usize {
        self.pk_script.as_bytes().len()
    }
}
