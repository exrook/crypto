#![feature(i128_type, never_type)]
extern crate blake2_rfc;
extern crate byteorder;
extern crate ring;
extern crate untrusted;

use std::collections::HashMap;

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
pub struct Balance(pub u128);

impl AsRef<[u8; 16]> for Balance {
    fn as_ref(&self) -> &[u8; 16] {
        unsafe { std::mem::transmute(&self.0) }
    }
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
        self.verify_sig(storage)
        // TODO: verify the account balance
    }
    fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        let pubkey = storage
            .find_open(self.previous)
            .ok_or(Failure::Missing)?
            .account;
        signature::verify(
            &ED25519,
            Input::from(&pubkey),
            Input::from(&self.hash()),
            Input::from(&self.signature),
        ).map_err(|_| Failure::Signature)
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
        let source = storage.lookup(self.source).ok_or(Failure::Missing)?;
        let source = match source {
            &Transaction::Send(ref s) => s,
            _ => return Err(Failure::Invalid),
        };
        if source.destination != pubkey {
            Err(Failure::Invalid)
        } else {
            Ok(())
        }
    }
    fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<PubKey, Failure> {
        let pubkey = storage
            .find_open(self.previous)
            .ok_or(Failure::Missing)?
            .account;
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
        let pubkey = storage
            .find_open(self.previous)
            .ok_or(Failure::Missing)?
            .account;
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
    fn lookup(&mut self, hash: Hash) -> Option<&Transaction>;
    fn find_head(&mut self, pubkey: PubKey) -> Option<&Hash>;
    fn find_open(&mut self, mut hash: Hash) -> Option<&OpenTransaction> {
        loop {
            match self.lookup(hash) {
                Some(&Transaction::Open(_)) => break,
                Some(&Transaction::Send(ref t)) => hash = t.previous.clone(),
                Some(&Transaction::Receive(ref t)) => hash = t.previous.clone(),
                Some(&Transaction::Change(ref t)) => hash = t.previous.clone(),
                None => return None,
            }
        }
        // This is a hack to get around the borrow checker
        match self.lookup(hash).unwrap() {
            &Transaction::Open(ref t) => Some(t),
            _ => unreachable!(),
        }
    }
}

struct Storage {
    transactions: HashMap<Hash, Transaction>,
    heads: HashMap<PubKey, Hash>,
}

impl BlockStorage for Storage {
    fn lookup(&mut self, hash: Hash) -> Option<&Transaction> {
        self.transactions.get(&hash)
    }
    fn find_head(&mut self, pubkey: PubKey) -> Option<&Hash> {
        self.heads.get(&pubkey)
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
    /// For a receive block, the referenced transaction has already been received
    Received,
    /// For a send block, the balance sent must be nonzero
    ZeroSend,
    /// A block this transaction references is missing
    Missing,
    /// This transaction is structurally invalid, e.x. an Open block that references a receive
    /// block or a change block as its source
    Invalid,
}

struct Blockchain {
    blocks: HashMap<Hash, Transaction>,
}

impl Blockchain {
    pub fn process(&mut self, transaction: Transaction) -> Result<(), ()> {
        unimplemented!()
    }
    //fn verify
}
