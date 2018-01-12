use blockstorage::{BlockStorage, Storage};
use transaction::{OpenTransaction, RaiHash, RaiWork, SendTransaction, Transaction};
use genesis::{BALANCE, TEST_BLOCK, TEST_PRIVATE_KEY};
use types::{Balance, Work};

use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use blake2::Blake2b;
use rand::{thread_rng, SeedableRng, XorShiftRng};

const TEST_SEED: [u32; 4] = [3435123151, 546876541, 146548468, 894165236];

#[test]
fn test_storage() {
    let mut s = Storage::new_test();
    let secret = SecretKey::from_bytes(&TEST_PRIVATE_KEY).unwrap();
    let public = PublicKey::from_secret::<Blake2b>(&secret);
    let keypair = Keypair { secret, public };
    let dest = Keypair::generate::<Blake2b>(&mut XorShiftRng::from_seed(TEST_SEED));
    let mut send = SendTransaction::new_without_work(
        &keypair,
        TEST_BLOCK.hash(),
        BALANCE - Balance(1),
        dest.public.into(),
    );
    send.work = Work(11670401854380690467);
    assert!(send.work_validate().verify());

    let mut open = OpenTransaction::new_without_work(&dest, send.hash(), None);
    println!("{:?}", open.work);
    open.work = Work(4421055909967421080);

    println!("Inserting send: {:?}", send);
    s.insert(send.into()).unwrap();
    println!("Inserting open: {:?}", open);
    s.insert(open.into()).unwrap();
    println!("{:#?}", s);
}
