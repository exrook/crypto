use std::collections::HashMap;

pub type Hash = u64;
pub type Work = u64;
pub type PubKey = String;
pub type Signature = String;
pub type Validation = (Work, Signature);
pub type Balance = u64; //TODO: Should be u128

pub enum Transaction {
    Open {
        account: PubKey,
        source: Hash,
        representative: PubKey,
        validation: Validation
    },
    Send {
        previous: Hash,
        balance: Balance,
        destination: PubKey,
        validation: Validation
    },
    Receive {
        previous: Hash,
        source: Hash,
        validation: Validation
    },
    Change {
        previous: Hash,
        representative: PubKey,
        validation: Validation
    }
}

struct Blockchain {
    blocks: HashMap<Hash, Transaction>
}

impl Blockchain {
    fn process(&mut self, transaction: Transaction) -> Result<(), ()> {
        unimplemented!()
    }
}
