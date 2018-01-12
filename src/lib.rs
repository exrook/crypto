#![feature(i128_type, never_type, try_from)]
extern crate blake2;
extern crate byteorder;
extern crate ed25519_dalek;
extern crate rand;

#[cfg(test)]
mod tests;
mod genesis;
mod transaction;
mod types;
mod blockstorage;
mod work;
mod errors {
    #[derive(Debug, Clone, PartialEq, Eq)]
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
}
