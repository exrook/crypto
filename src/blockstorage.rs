use std::collections::{HashMap, HashSet};

use transaction::{OpenTransaction, RaiHash, Transaction};
use types::{Balance, Hash, PubKey};
use errors::Failure;
use genesis;

pub trait BlockStorage {
    /// Lookup a transaction based on its hash
    fn lookup(&mut self, hash: Hash) -> Option<&Transaction>;
    /// Find the most recent transaction belonging to an account
    fn find_head(&mut self, pubkey: PubKey) -> Option<Hash>;
    /// Find the public key that used to sign a given block
    fn find_key(&mut self, hash: Hash) -> Option<PubKey> {
        self.find_open(hash).map(|o| o.account)
    }
    /// Find the first transaction in an account's ledger
    fn find_open(&mut self, mut hash: Hash) -> Option<&OpenTransaction> {
        // The first lookup can fail, which is why we do this
        hash = match self.lookup(hash)? {
            &Transaction::Open(_) => hash,
            &Transaction::Send(ref t) => t.previous,
            &Transaction::Receive(ref t) => t.previous,
            &Transaction::Change(ref t) => t.previous,
        };
        loop {
            match self.lookup(hash) {
                Some(&Transaction::Open(_)) => break,
                Some(&Transaction::Send(ref t)) => hash = t.previous.clone(),
                Some(&Transaction::Receive(ref t)) => hash = t.previous.clone(),
                Some(&Transaction::Change(ref t)) => hash = t.previous.clone(),
                None => unreachable!(), // This should only ever happen if the ledger is in an invalid state
            }
        }
        // This is a hack to get around the borrow checker
        match self.lookup(hash).unwrap() {
            &Transaction::Open(ref t) => Some(t),
            _ => unreachable!(),
        }
    }
    /// Find the balance in the account at the time of the given transaction
    fn find_balance(&mut self, hash: Hash) -> Option<Balance>;
    /// Given the hash of a send block, check if it has been spent yet
    fn is_unspent(&mut self, hash: Hash) -> bool;

    /// Try to insert a new transaction
    fn insert(&mut self, tx: Transaction) -> Result<(), Failure>;
    //fn calculate_balance(&mut self, mut hash: Hash) -> Option<u128> {
    //    let mut bal = 0;
    //    loop {
    //        let (next, leaf) = match self.lookup(next) {
    //            Some(&Transaction::Open(ref o)) => (None, o.source),
    //            Some(&Transaction::Receive(ref r)) => (Some(r.previous), r.source),
    //            Some(&Transaction::Send(ref s)) => {
    //                bal += s.balance;
    //                return Some(bal);
    //            }
    //            Some(&Transaction::Change(ref c)) => {}
    //            None => return None,
    //        };
    //        match self.lookup(leaf) {
    //            Some(&Transaction::Send(ref s)) => bal,
    //            _ => unreachable!(),
    //        }
    //        if let Some(next) = next {
    //            hash = next;
    //        } else {
    //            return Some(balance);
    //        }
    //    }
    //}
}

pub struct Storage {
    transactions: HashMap<Hash, (Transaction, Balance)>,
    heads: HashMap<PubKey, Hash>,
    unspent: HashSet<Hash>,
}

impl Storage {
    /// Create a new BlockStorage
    pub fn new() -> Self {
        let mut transactions = HashMap::new();
        let mut heads = HashMap::new();
        let unspent = HashSet::new();
        transactions.insert(
            genesis::LIVE_BLOCK.hash(),
            (Transaction::Open(genesis::LIVE_BLOCK), genesis::BALANCE),
        );
        heads.insert(genesis::LIVE_BLOCK.account, genesis::LIVE_BLOCK.hash());
        Self {
            transactions,
            heads,
            unspent,
        }
    }
    fn new_test() -> Self {
        let mut transactions = HashMap::new();
        let mut heads = HashMap::new();
        let unspent = HashSet::new();
        transactions.insert(
            genesis::TEST_BLOCK.hash(),
            (Transaction::Open(genesis::TEST_BLOCK), genesis::BALANCE),
        );
        heads.insert(genesis::TEST_BLOCK.account, genesis::TEST_BLOCK.hash());
        Self {
            transactions,
            heads,
            unspent,
        }
    }
}

impl BlockStorage for Storage {
    fn lookup(&mut self, hash: Hash) -> Option<&Transaction> {
        self.transactions.get(&hash).map(|&(ref t, _)| t)
    }
    fn find_head(&mut self, pubkey: PubKey) -> Option<Hash> {
        self.heads.get(&pubkey).map(|&x| x)
    }
    fn find_balance(&mut self, hash: Hash) -> Option<Balance> {
        self.transactions.get(&hash).map(|&(_, b)| b)
    }
    fn is_unspent(&mut self, hash: Hash) -> bool {
        self.unspent.contains(&hash)
    }
    fn insert(&mut self, tx: Transaction) -> Result<(), Failure> {
        tx.verify(self)?;
        use transaction::Transaction::*;
        let (bal, key, parent) = match tx {
            Open(ref o) => {
                // Find the balance of this account by finding the amount
                let bal = self.find_balance(o.source).ok_or(Failure::Unreachable)?;
                let prev = match self.lookup(o.source).ok_or(Failure::Unreachable)? {
                    &Send(ref s) => s.previous,
                    _ => return Err(Failure::Invalid),
                };
                let prev_bal = self.find_balance(prev).ok_or(Failure::Unreachable)?;
                let bal = prev_bal - bal;
                (bal, o.account, None)
            }
            Receive(ref r) => {
                // Find the balance of this account by finding the amount
                let bal = self.find_balance(r.source).ok_or(Failure::Unreachable)?;
                let prev = match self.lookup(r.source).ok_or(Failure::Unreachable)? {
                    &Send(ref s) => s.previous,
                    _ => return Err(Failure::Invalid),
                };
                let prev_bal = self.find_balance(prev).ok_or(Failure::Unreachable)?;
                let gain = prev_bal - bal;
                let bal = self.find_balance(r.previous).ok_or(Failure::Unreachable)? + gain;
                let key = self.find_key(r.previous).ok_or(Failure::Unreachable)?;
                (bal, key, Some(r.previous))
            }
            Send(ref s) => (
                s.balance,
                self.find_key(s.previous).ok_or(Failure::Unreachable)?,
                Some(s.previous),
            ),
            Change(ref c) => (
                self.find_balance(c.previous).ok_or(Failure::Unreachable)?,
                self.find_key(c.previous).ok_or(Failure::Unreachable)?,
                Some(c.previous),
            ),
        };
        if self.find_head(key) != parent {
            return Err(Failure::Fork);
        }
        let hash = tx.hash();
        self.transactions.insert(hash, (tx, bal));
        self.heads.insert(key, hash);
        panic!()
    }
}
