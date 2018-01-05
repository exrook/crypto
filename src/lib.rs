#![feature(i128_type, never_type)]
extern crate blake2_rfc;
extern crate byteorder;
extern crate ring;
extern crate untrusted;

use std::collections::{HashMap, HashSet};

use ring::signature;
use ring::signature::ED25519;
use untrusted::Input;
use blake2_rfc::blake2b::Blake2b;
use byteorder::{ByteOrder, LE};

pub type Hash = [u8; 32];
pub type PubKey = [u8; 32];
pub type Signature = [u8; 64];
#[derive(Copy, Clone)]
pub struct Work(u64);

impl AsRef<[u8; 8]> for Work {
    fn as_ref(&self) -> &[u8; 8] {
        unsafe { std::mem::transmute(&self.0) }
    }
}
#[derive(Copy, Clone, Debug)]
pub struct WorkHash([u8; 8]);
impl WorkHash {
    const RAI_WORK_THRESHOLD: u64 = 0xffffffc000000000;
}
impl Into<u64> for WorkHash {
    fn into(self) -> u64 {
        LE::read_u64(&self.0)
    }
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Balance(pub u128);

impl AsRef<[u8; 16]> for Balance {
    fn as_ref(&self) -> &[u8; 16] {
        unsafe { std::mem::transmute(&self.0) }
    }
}

impl std::ops::Add for Balance {
    type Output = Balance;
    fn add(self, rhs: Self) -> Balance {
        Balance(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Balance {
    type Output = Balance;
    fn sub(self, rhs: Self) -> Balance {
        Balance(self.0 - rhs.0)
    }
}

mod genesis {
    use {Balance, Hash, OpenTransaction, PubKey, Signature, Work};

    pub const BALANCE: Balance = Balance(u128::max_value());
    // These are intentionally the same, apparently
    const LIVE_KEY: PubKey = [
        0xE8, 0x92, 0x08, 0xDD, 0x03, 0x8F, 0xBB, 0x26, 0x99, 0x87, 0x68, 0x96, 0x21, 0xD5, 0x22,
        0x92, 0xAE, 0x9C, 0x35, 0x94, 0x1A, 0x74, 0x84, 0x75, 0x6E, 0xCC, 0xED, 0x92, 0xA6, 0x50,
        0x93, 0xBA,
    ];
    const LIVE_SOURCE: Hash = [
        0xE8, 0x92, 0x08, 0xDD, 0x03, 0x8F, 0xBB, 0x26, 0x99, 0x87, 0x68, 0x96, 0x21, 0xD5, 0x22,
        0x92, 0xAE, 0x9C, 0x35, 0x94, 0x1A, 0x74, 0x84, 0x75, 0x6E, 0xCC, 0xED, 0x92, 0xA6, 0x50,
        0x93, 0xBA,
    ];
    const LIVE_WORK: Work = Work(0x62f05417dd3fb691);
    const LIVE_SIGNATURE: Signature = [
        0x9F, 0x0C, 0x93, 0x3C, 0x8A, 0xDE, 0x00, 0x4D, 0x80, 0x8E, 0xA1, 0x98, 0x5F, 0xA7, 0x46,
        0xA7, 0xE9, 0x5B, 0xA2, 0xA3, 0x8F, 0x86, 0x76, 0x40, 0xF5, 0x3E, 0xC8, 0xF1, 0x80, 0xBD,
        0xFE, 0x9E, 0x2C, 0x12, 0x68, 0xDE, 0xAD, 0x7C, 0x26, 0x64, 0xF3, 0x56, 0xE3, 0x7A, 0xBA,
        0x36, 0x2B, 0xC5, 0x8E, 0x46, 0xDB, 0xA0, 0x3E, 0x52, 0x3A, 0x7B, 0x5A, 0x19, 0xE4, 0xB6,
        0xEB, 0x12, 0xBB, 0x02,
    ];
    pub const LIVE_BLOCK: OpenTransaction = OpenTransaction {
        account: LIVE_KEY,
        source: LIVE_SOURCE,
        representative: LIVE_KEY,
        work: LIVE_WORK,
        signature: LIVE_SIGNATURE,
    };

    const TEST_PRIVATE_KEY: [u8; 32] = [
        0x34, 0xF0, 0xA3, 0x7A, 0xAD, 0x20, 0xF4, 0xA2, 0x60, 0xF0, 0xA5, 0xB3, 0xCB, 0x3D, 0x7F,
        0xB5, 0x06, 0x73, 0x21, 0x22, 0x63, 0xE5, 0x8A, 0x38, 0x0B, 0xC1, 0x04, 0x74, 0xBB, 0x03,
        0x9C, 0xE4,
    ];
    const TEST_KEY: PubKey = [
        0xB0, 0x31, 0x1E, 0xA5, 0x57, 0x08, 0xD6, 0xA5, 0x3C, 0x75, 0xCD, 0xBF, 0x88, 0x30, 0x02,
        0x59, 0xC6, 0xD0, 0x18, 0x52, 0x2F, 0xE3, 0xD4, 0xD0, 0xA2, 0x42, 0xE4, 0x31, 0xF9, 0xE8,
        0xB6, 0xD0,
    ];
    const TEST_SOURCE: Hash = [
        0xB0, 0x31, 0x1E, 0xA5, 0x57, 0x08, 0xD6, 0xA5, 0x3C, 0x75, 0xCD, 0xBF, 0x88, 0x30, 0x02,
        0x59, 0xC6, 0xD0, 0x18, 0x52, 0x2F, 0xE3, 0xD4, 0xD0, 0xA2, 0x42, 0xE4, 0x31, 0xF9, 0xE8,
        0xB6, 0xD0,
    ];
    const TEST_WORK: Work = Work(0x9680625b39d3363d);
    const TEST_SIGNATURE: Signature = [
        0xEC, 0xDA, 0x91, 0x43, 0x73, 0xA2, 0xF0, 0xCA, 0x12, 0x96, 0x47, 0x5B, 0xAE, 0xE4, 0x05,
        0x00, 0xA7, 0xF0, 0xA7, 0xAD, 0x72, 0xA5, 0xA8, 0x0C, 0x81, 0xD7, 0xFA, 0xB7, 0xF6, 0xC8,
        0x02, 0xB2, 0xCC, 0x7D, 0xB5, 0x0F, 0x5D, 0xD0, 0xFB, 0x25, 0xB2, 0xEF, 0x11, 0x76, 0x1F,
        0xA7, 0x34, 0x4A, 0x15, 0x8D, 0xD5, 0xA7, 0x00, 0xB2, 0x1B, 0xD4, 0x7D, 0xE5, 0xBD, 0x0F,
        0x63, 0x15, 0x3A, 0x02,
    ];
    pub const TEST_BLOCK: OpenTransaction = OpenTransaction {
        account: TEST_KEY,
        source: TEST_SOURCE,
        representative: TEST_KEY,
        work: TEST_WORK,
        signature: TEST_SIGNATURE,
    };
}

pub trait RaiHash {
    fn hash(&self) -> Hash;
}

trait RaiHashImpl<'a> {
    type Elements: AsRef<[&'a [u8]]>;
    #[inline]
    fn hash_elements(&'a self) -> Self::Elements;
    fn hash_impl(&'a self) -> Hash {
        let mut hash = Blake2b::new(32);
        for e in self.hash_elements().as_ref() {
            hash.update(e)
        }
        let hash = hash.finalize();
        let bytes = hash.as_bytes();
        assert_eq!(bytes.len(), 32);
        let mut out = Hash::default();
        out.copy_from_slice(bytes);
        out
    }
}

impl<T: for<'a> RaiHashImpl<'a>> RaiHash for T {
    fn hash(&self) -> Hash {
        {
            self.hash_impl()
        }
    }
}

pub trait RaiWork {
    fn verify_work(&self) -> Result<(), Failure> {
        let work: u64 = self.work_validate().into();
        if work < WorkHash::RAI_WORK_THRESHOLD {
            Ok(())
        } else {
            Err(Failure::Work)
        }
    }
    fn work_validate(&self) -> WorkHash;
    fn work_calculate(&self, Work) -> WorkHash;
}

trait RaiWorkImpl {
    fn work_element(&self) -> &[u8];
    fn work_value(&self) -> Work;
    fn work_impl(&self, work: Work) -> WorkHash {
        let mut hash = Blake2b::new(8);
        hash.update(work.as_ref());
        hash.update(self.work_element());
        let hash = hash.finalize();
        let bytes = hash.as_bytes();
        assert_eq!(bytes.len(), 8);
        let mut out = <[u8; 8]>::default();
        out.copy_from_slice(bytes);
        WorkHash(out)
    }
}

impl<T: RaiWorkImpl> RaiWork for T {
    fn work_validate(&self) -> WorkHash {
        self.work_impl(self.work_value())
    }
    fn work_calculate(&self, work: Work) -> WorkHash {
        self.work_impl(work)
    }
}

pub enum Transaction {
    Open(OpenTransaction),
    Send(SendTransaction),
    Receive(ReceiveTransaction),
    Change(ChangeTransaction),
}

impl Transaction {
    /// Verify this transaction's signature
    fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        use Transaction::*;
        match self {
            &Open(ref o) => o.verify(storage),
            &Send(ref s) => s.verify(storage),
            &Receive(ref r) => r.verify(storage),
            &Change(ref c) => c.verify(storage),
        }
    }
}

impl RaiHash for Transaction {
    fn hash(&self) -> Hash {
        use Transaction::*;
        match self {
            &Open(ref o) => o.hash(),
            &Send(ref s) => s.hash(),
            &Receive(ref r) => r.hash(),
            &Change(ref c) => c.hash(),
        }
    }
}

pub struct OpenTransaction {
    account: PubKey,
    source: Hash,
    representative: PubKey,
    work: Work,
    signature: Signature,
}

impl OpenTransaction {
    fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_sig()?;
        self.verify_work()?;
        self.verify_parent(storage)
    }
    fn verify_parent<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        let source = storage.lookup(self.source).ok_or(Failure::Missing)?;
        let source = match source {
            &Transaction::Send(ref s) => s,
            _ => return Err(Failure::Invalid),
        };
        if source.destination != self.account {
            Err(Failure::Invalid)
        } else {
            Ok(())
        }
    }
    fn verify_sig(&self) -> Result<(), Failure> {
        signature::verify(
            &ED25519,
            Input::from(&self.account),
            Input::from(&self.hash()),
            Input::from(&self.signature),
        ).map_err(|_| Failure::Signature)
    }
}
impl<'a> RaiHashImpl<'a> for OpenTransaction {
    type Elements = [&'a [u8]; 3];
    fn hash_elements(&'a self) -> [&'a [u8]; 3] {
        [&self.source, &self.representative, &self.account]
    }
}

impl RaiWorkImpl for OpenTransaction {
    fn work_element(&self) -> &[u8] {
        &self.account
    }
    fn work_value(&self) -> Work {
        self.work
    }
}

pub struct SendTransaction {
    previous: Hash,
    balance: Balance,
    destination: PubKey,
    work: Work,
    signature: Signature,
}

impl SendTransaction {
    fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_work()?;
        let pubkey = self.verify_sig(storage)?;
        self.verify_balance(storage, pubkey)
    }
    fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<PubKey, Failure> {
        let pubkey = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        signature::verify(
            &ED25519,
            Input::from(&pubkey),
            Input::from(&self.hash()),
            Input::from(&self.signature),
        ).map_err(|_| Failure::Signature)?;
        Ok(pubkey)
    }
    fn verify_balance<S: BlockStorage>(
        &self,
        storage: &mut S,
        pubkey: PubKey,
    ) -> Result<(), Failure> {
        let bal = storage.find_balance(pubkey).ok_or(Failure::Unreachable)?;
        if self.balance > bal {
            Err(Failure::OverSend)
        } else {
            Ok(())
        }
    }
}

impl<'a> RaiHashImpl<'a> for SendTransaction {
    type Elements = [&'a [u8]; 3];
    fn hash_elements(&'a self) -> [&'a [u8]; 3] {
        [&self.previous, &self.destination, self.balance.as_ref()]
    }
}

impl RaiWorkImpl for SendTransaction {
    fn work_element(&self) -> &[u8] {
        &self.previous
    }
    fn work_value(&self) -> Work {
        self.work
    }
}

pub struct ReceiveTransaction {
    previous: Hash,
    source: Hash,
    work: Work,
    signature: Signature,
}

impl ReceiveTransaction {
    fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_work()?;
        let pubkey = self.verify_sig(storage)?;
        self.verify_parent(storage, pubkey)
    }
    fn verify_parent<S: BlockStorage>(
        &self,
        storage: &mut S,
        pubkey: PubKey,
    ) -> Result<(), Failure> {
        {
            let source = storage.lookup(self.source).ok_or(Failure::Missing)?;
            let source = match source {
                &Transaction::Send(ref s) => s,
                _ => return Err(Failure::Invalid),
            };
            if source.destination != pubkey {
                return Err(Failure::Invalid);
            }
        }
        if storage.is_unspent(self.source) {
            Ok(())
        } else {
            Err(Failure::Received)
        }
    }
    fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<PubKey, Failure> {
        let pubkey = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        signature::verify(
            &ED25519,
            Input::from(&pubkey),
            Input::from(&self.hash()),
            Input::from(&self.signature),
        ).map_err(|_| Failure::Signature)?;
        Ok(pubkey)
    }
}

impl<'a> RaiHashImpl<'a> for ReceiveTransaction {
    type Elements = [&'a [u8]; 2];
    fn hash_elements(&'a self) -> [&'a [u8]; 2] {
        [&self.previous, &self.source]
    }
}

impl RaiWorkImpl for ReceiveTransaction {
    fn work_element(&self) -> &[u8] {
        &self.previous
    }
    fn work_value(&self) -> Work {
        self.work
    }
}

pub struct ChangeTransaction {
    previous: Hash,
    representative: PubKey,
    work: Work,
    signature: Signature,
}

impl ChangeTransaction {
    fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_sig(storage)?;
        self.verify_work()
    }
    fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        let pubkey = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        signature::verify(
            &ED25519,
            Input::from(&pubkey),
            Input::from(&self.hash()),
            Input::from(&self.signature),
        ).map_err(|_| Failure::Signature)
    }
}

impl<'a> RaiHashImpl<'a> for ChangeTransaction {
    type Elements = [&'a [u8]; 2];
    fn hash_elements(&'a self) -> [&'a [u8]; 2] {
        [&self.previous, &self.representative]
    }
}

impl RaiWorkImpl for ChangeTransaction {
    fn work_element(&self) -> &[u8] {
        &self.previous
    }
    fn work_value(&self) -> Work {
        self.work
    }
}

trait BlockStorage {
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
        use Transaction::*;
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

pub enum Failure {
    /// The transaction is already recorded
    Duplicate,
    /// The signature is invalid
    Signature,
    /// The transaction's parent is not the head of the owner's account
    Fork,
    /// The provided PoW is invalid
    Work,
    /// For a receive block, the referenced transaction has already been received/spent
    Received,
    /// For a send block, the balance sent must be nonzero
    ZeroSend,
    /// For a send block, the balance sent must be less than or equal to the account balance
    OverSend,
    /// A block this transaction references is missing
    Missing,
    /// This transaction is structurally invalid, e.x. an Open block that references a receive
    /// block or a change block as its source
    Invalid,
    /// This error should not happen, if it does there is a bug
    Unreachable,
}
