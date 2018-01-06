use std;
use byteorder::{ByteOrder, BE, LE};

pub type Hash = [u8; 32];
pub type PubKey = [u8; 32];
pub type Signature = [u8; 64];
#[derive(Copy, Clone)]
pub struct Work(pub u64);

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
        ({let w: u64 = (*self).into(); w} > WorkHash::RAI_WORK_THRESHOLD)
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
