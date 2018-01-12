use std::convert::TryInto;
use ed25519_dalek as ed25519;
use blake2::Blake2b;
use blake2::digest::{Input, VariableOutput};

use types::{Balance, Hash, PubKey, Signature, Work, WorkHash};
use errors::Failure;
use blockstorage::BlockStorage;
use work::compute_work;

pub trait RaiHash {
    fn hash(&self) -> Hash;
}

pub trait RaiHashImpl<'a> {
    type Elements: AsRef<[&'a [u8]]>;
    #[inline]
    fn hash_elements(&'a self) -> Self::Elements;
    fn hash_impl(&'a self) -> Hash {
        let mut hash = Blake2b::new(32).expect("Unreachable");
        for e in self.hash_elements().as_ref() {
            hash.process(e)
        }
        let mut bytes = Hash::default();
        hash.variable_result(&mut bytes).expect("Unreachable");
        bytes
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
        if self.work_validate().verify() {
            Ok(())
        } else {
            Err(Failure::Work)
        }
    }
    fn work_validate(&self) -> WorkHash;
    fn work_calculate(&self, Work) -> WorkHash;
}

pub trait RaiWorkImpl {
    fn work_element(&self) -> &[u8];
    fn work_value(&self) -> Work;
    fn work_impl(&self, work: Work) -> WorkHash {
        let mut hash = Blake2b::new(8).expect("Unreachable");
        hash.process(work.as_ref());
        hash.process(self.work_element());
        let mut bytes = <[u8; 8]>::default();
        hash.variable_result(&mut bytes).expect("Unreachable");
        WorkHash(bytes)
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

#[derive(Debug)]
pub enum Transaction {
    Open(OpenTransaction),
    Send(SendTransaction),
    Receive(ReceiveTransaction),
    Change(ChangeTransaction),
}

impl Transaction {
    /// Verify this transaction's signature
    pub fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        use transaction::Transaction::*;
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
        use transaction::Transaction::*;
        match self {
            &Open(ref o) => o.hash(),
            &Send(ref s) => s.hash(),
            &Receive(ref r) => r.hash(),
            &Change(ref c) => c.hash(),
        }
    }
}

#[derive(Debug)]
pub struct OpenTransaction {
    pub account: PubKey,
    pub source: Hash,
    pub representative: PubKey,
    pub work: Work,
    pub signature: Signature,
}

impl OpenTransaction {
    pub fn new(key: &ed25519::Keypair, source: Hash, rep: Option<PubKey>) -> Self {
        let mut o = Self::new_without_work(key, source, rep);
        o.work = compute_work(&o);
        o
    }
    pub fn new_without_work(key: &ed25519::Keypair, source: Hash, rep: Option<PubKey>) -> Self {
        let mut o = Self {
            account: key.public.to_bytes().into(),
            source,
            representative: rep.unwrap_or(key.public.to_bytes().into()),
            work: Work::default(),
            signature: Signature::default(),
        };
        o.signature = key.sign::<Blake2b>(&o.hash()).to_bytes().into();
        o
    }
    pub fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_sig()?;
        self.verify_work()?;
        self.verify_parent(storage)
    }
    pub(crate) fn verify_parent<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        {
            let source = storage.lookup(self.source).ok_or(Failure::Missing)?;
            let source = match source {
                &Transaction::Send(ref s) => s,
                _ => return Err(Failure::Invalid),
            };
            if source.destination != self.account {
                return Err(Failure::Invalid);
            }
        }
        if storage.is_unspent(self.source) {
            Ok(())
        } else {
            Err(Failure::Received)
        }
    }
    pub(crate) fn verify_sig(&self) -> Result<(), Failure> {
        let pubkey: ed25519::PublicKey = self.account.try_into()?;
        let sig = self.signature.try_into()?;
        match pubkey.verify::<Blake2b>(&self.hash(), &sig) {
            true => Ok(()),
            false => Err(Failure::Signature),
        }
    }
}
impl<'a> RaiHashImpl<'a> for OpenTransaction {
    type Elements = [&'a [u8]; 3];
    fn hash_elements(&'a self) -> [&'a [u8]; 3] {
        [
            &self.source,
            self.representative.as_ref(),
            self.account.as_ref(),
        ]
    }
}

impl RaiWorkImpl for OpenTransaction {
    fn work_element(&self) -> &[u8] {
        self.account.as_ref()
    }
    fn work_value(&self) -> Work {
        self.work
    }
}

impl Into<Transaction> for OpenTransaction {
    fn into(self) -> Transaction {
        Transaction::Open(self)
    }
}

#[derive(Debug)]
pub struct SendTransaction {
    pub previous: Hash,
    pub balance: Balance,
    pub destination: PubKey,
    pub work: Work,
    pub signature: Signature,
}

impl SendTransaction {
    pub fn new(
        key: &ed25519::Keypair,
        previous: Hash,
        balance: Balance,
        destination: PubKey,
    ) -> Self {
        let mut o = Self::new_without_work(key, previous, balance, destination);
        o.work = compute_work(&o);
        o
    }
    pub fn new_without_work(
        key: &ed25519::Keypair,
        previous: Hash,
        balance: Balance,
        destination: PubKey,
    ) -> Self {
        let mut o = Self {
            previous,
            balance,
            destination,
            work: Work::default(),
            signature: Signature::default(),
        };
        o.signature = key.sign::<Blake2b>(&o.hash()).into();
        o
    }
    pub(crate) fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_work()?;
        let pubkey = self.verify_sig(storage)?;
        self.verify_balance(storage)
    }
    pub(crate) fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<PubKey, Failure> {
        let pubkey_bytes = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        let pubkey: ed25519::PublicKey = pubkey_bytes.try_into()?;
        let sig = self.signature.try_into()?;
        match pubkey.verify::<Blake2b>(&self.hash(), &sig) {
            true => Ok(pubkey_bytes),
            false => Err(Failure::Signature),
        }
    }
    pub(crate) fn verify_balance<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        let bal = storage
            .find_balance(self.previous)
            .ok_or(Failure::Unreachable)?;
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
        [
            &self.previous,
            self.destination.as_ref(),
            self.balance.as_ref(),
        ]
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

impl Into<Transaction> for SendTransaction {
    fn into(self) -> Transaction {
        Transaction::Send(self)
    }
}

#[derive(Debug)]
pub struct ReceiveTransaction {
    pub previous: Hash,
    pub source: Hash,
    pub work: Work,
    pub signature: Signature,
}

impl ReceiveTransaction {
    pub fn new(key: &ed25519::Keypair, previous: Hash, source: Hash) -> Self {
        let mut o = Self::new_without_work(key, previous, source);
        o.work = compute_work(&o);
        o
    }
    pub fn new_without_work(key: &ed25519::Keypair, previous: Hash, source: Hash) -> Self {
        let mut o = Self {
            previous,
            source,
            work: Work::default(),
            signature: Signature::default(),
        };
        o.signature = key.sign::<Blake2b>(&o.hash()).into();
        o
    }
    pub(crate) fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_work()?;
        let pubkey = self.verify_sig(storage)?;
        self.verify_parent(storage, pubkey)
    }
    pub(crate) fn verify_parent<S: BlockStorage>(
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
    pub(crate) fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<PubKey, Failure> {
        let pubkey_bytes = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        let pubkey: ed25519::PublicKey = pubkey_bytes.try_into()?;
        let sig = self.signature.try_into()?;
        match pubkey.verify::<Blake2b>(&self.hash(), &sig) {
            true => Ok(pubkey_bytes),
            false => Err(Failure::Signature),
        }
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

impl Into<Transaction> for ReceiveTransaction {
    fn into(self) -> Transaction {
        Transaction::Receive(self)
    }
}

#[derive(Debug)]
pub struct ChangeTransaction {
    pub previous: Hash,
    pub representative: PubKey,
    pub work: Work,
    pub signature: Signature,
}

impl ChangeTransaction {
    pub fn new(key: &ed25519::Keypair, previous: Hash, rep: PubKey) -> Self {
        let mut o = Self::new_without_work(key, previous, rep);
        o.work = compute_work(&o);
        o
    }
    pub fn new_without_work(key: &ed25519::Keypair, previous: Hash, rep: PubKey) -> Self {
        let mut o = Self {
            previous,
            representative: rep,
            work: Work::default(),
            signature: Signature::default(),
        };
        o.signature = key.sign::<Blake2b>(&o.hash()).into();
        o
    }
    pub(crate) fn verify<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        self.verify_sig(storage)?;
        self.verify_work()
    }
    pub(crate) fn verify_sig<S: BlockStorage>(&self, storage: &mut S) -> Result<(), Failure> {
        let pubkey_bytes = storage.find_key(self.previous).ok_or(Failure::Missing)?;
        let pubkey: ed25519::PublicKey = pubkey_bytes.try_into()?;
        let sig = self.signature.try_into()?;
        match pubkey.verify::<Blake2b>(&self.hash(), &sig) {
            true => Ok(()),
            false => Err(Failure::Signature),
        }
    }
}

impl<'a> RaiHashImpl<'a> for ChangeTransaction {
    type Elements = [&'a [u8]; 2];
    fn hash_elements(&'a self) -> [&'a [u8]; 2] {
        [&self.previous, self.representative.as_ref()]
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

impl Into<Transaction> for ChangeTransaction {
    fn into(self) -> Transaction {
        Transaction::Change(self)
    }
}
