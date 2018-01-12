use std;
use std::convert::TryInto;
use byteorder::{ByteOrder, BE, LE};
use rand::{Rand, Rng};
use ed25519_dalek as ed25519;

use errors::Failure;

pub type Hash = [u8; 32];

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct PubKey(pub(crate) [u8; 32]);

impl From<[u8; 32]> for PubKey {
    fn from(key: [u8; 32]) -> PubKey {
        PubKey(key)
    }
}

impl From<ed25519::PublicKey> for PubKey {
    fn from(key: ed25519::PublicKey) -> PubKey {
        PubKey(key.to_bytes())
    }
}

impl TryInto<ed25519::PublicKey> for PubKey {
    type Error = Failure;
    fn try_into(self) -> Result<ed25519::PublicKey, Failure> {
        ed25519::PublicKey::from_bytes(&self.0).map_err(|_| Failure::Signature)
    }
}

impl AsRef<[u8; 32]> for PubKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Copy, Clone)]
pub struct Signature(pub(crate) [u8; 64]);

impl Default for Signature {
    fn default() -> Signature {
        Signature([0; 64])
    }
}

impl ::std::fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        ::std::fmt::Debug::fmt(self.0.as_ref(), fmt)
    }
}

impl From<[u8; 64]> for Signature {
    fn from(sig: [u8; 64]) -> Signature {
        Signature(sig)
    }
}

impl From<ed25519::Signature> for Signature {
    fn from(sig: ed25519::Signature) -> Signature {
        sig.to_bytes().into()
    }
}

impl TryInto<ed25519::Signature> for Signature {
    type Error = Failure;
    fn try_into(self) -> Result<ed25519::Signature, Failure> {
        ed25519::Signature::from_bytes(&self.0).map_err(|_| Failure::Signature)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Work(pub u64);

impl Default for Work {
    fn default() -> Work {
        Work(0)
    }
}

impl Rand for Work {
    fn rand<R: Rng>(rand: &mut R) -> Self {
        Work(rand.gen())
    }
}

impl AsRef<[u8; 8]> for Work {
    fn as_ref(&self) -> &[u8; 8] {
        unsafe { std::mem::transmute(&self.0) }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct WorkHash(pub [u8; 8]);
impl WorkHash {
    pub const RAI_WORK_THRESHOLD: u64 = 0xffffffc000000000;
    pub fn verify(&self) -> bool {
        let w: u64 = (*self).into();
        (w > WorkHash::RAI_WORK_THRESHOLD)
    }
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
