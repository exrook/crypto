use types::Work;
use transaction::RaiWork;
use rand::{random, Rng, XorShiftRng};

pub fn compute_work<T: RaiWork>(tx: &T) -> Work {
    let mut rng = random::<XorShiftRng>();
    loop {
        let work = rng.gen();
        if tx.work_calculate(work).verify() {
            return work;
        }
    }
}
