//! Birthday paradox PoC
//!
//! A collision should be found after ≈ √|D| extractions, with D the set from
//! where the values are (uniformly) randomly fetched.
//!
//! The PoC is given using two separate methods to generate (pseudo)-random
//! values:
//! - using a subset of the bytes produced by applying SHA2 to a counter
//! - using the `rand::thread_rng`, a thread-local random number generator
//!   seeded by the system.
//!
//! For some background see https://datawok.net/posts/birthday-paradox

use rand::Rng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub fn sub_sha_collisions(num_bytes: usize) {
    let mut rng = rand::thread_rng();
    let mut set = HashMap::new();
    let set_size = 1_u128 << (num_bytes * 8);
    let mut curr = rng.gen_range(0..set_size);

    let sha256 = |data, len| {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let res = hasher.finalize();
        res[..len].to_vec()
    };

    let mut count = 0;
    loop {
        count += 1;
        curr = curr.wrapping_add(1);

        let hash = sha256(curr.to_le_bytes(), num_bytes);
        if let Some(old) = set.insert(hash, curr) {
            println!("Collision after {:?} hashes", count);
            let old_sha = sha256(old.to_le_bytes(), 32);
            let new_sha = sha256(curr.to_le_bytes(), 32);
            println!(
                "{}-{} = H({})",
                hex::encode(&old_sha[..num_bytes]),
                hex::encode(&old_sha[num_bytes..]),
                old,
            );
            println!(
                "{}-{} = H({})",
                hex::encode(&new_sha[..num_bytes]),
                hex::encode(&new_sha[num_bytes..]),
                curr,
            );
            break;
        }
    }
}

pub fn os_rand_collisions(num_bytes: usize) {
    let mut set = HashSet::new();
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; num_bytes];

    let mut count = 0;
    loop {
        count += 1;
        rng.fill_bytes(&mut buf);
        if !set.insert(buf.clone()) {
            println!("Collision after {:?} extractions", count);
            println!("Value: {}", hex::encode(&buf));
            break;
        }
    }
}

fn main() {
    let num_bytes = 6;

    println!("Search set size: {}", 1_u128 << (num_bytes * 8));
    println!(
        "First collision expected after: {}",
        1_u128 << (num_bytes * 4)
    );

    println!("Random value obtained via thread rng");
    os_rand_collisions(num_bytes);

    println!("Random value obtained via sha256(counter)");
    sub_sha_collisions(num_bytes);
}
