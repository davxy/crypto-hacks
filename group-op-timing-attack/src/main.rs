//! Timing attack simulation for a device implementing some form of group operation
//! not in constant time.
//!
//! For example, given a message `m` and a secret `d`, it can simulate:
//! - m^d mod n using "square and multiply"
//! - d·m mod n using "double and add"
//!
//! The secret is recovered using the
//! [variance difference strategy](https://datawok.net/posts/timing-attack).
//!
//! It is a probabilistic attack in nature, so you may not be successfull on the
//! first run.
//!
//! The execution times of group operations are not fixed but vary with the value
//! of `m`. If `m` is chosen randomly, these times follow a Gaussian distribution
//! with a configurable mean μ and standard deviation σ (with default μ = 1000
//! and σ = 50).

use num_bigint::{BigUint, RandBigInt};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_distr::{Distribution, Normal};
use std::io::{self, Write};
use std::str::FromStr;

fn get_modulus(keylen: u64) -> BigUint {
    match keylen {
        8 => BigUint::from(61_u8),
        16 => BigUint::from(53759_u16),
        32 => BigUint::from(2675797811_u32),
        64 => BigUint::from(8642890157798231327_u64),
        128 => BigUint::from(249018405283997733407297959207515566297_u128),
        256 => BigUint::from_str(
            "44836394558820158783687605622545866580915032641323282158738215690847176590297",
        )
        .unwrap(),
        _ => panic!("Not supported keylen"),
    }
}

fn square_and_multiply(m: &BigUint, d: &BigUint, p: &BigUint) -> f64 {
    let mut res = BigUint::from(1u64);
    let mut delay = 0.0;

    let seed = m.iter_u64_digits().next().unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let normal = Normal::new(1000.0, 50.0).unwrap();

    let mut nbits = d.bits();
    if nbits == 0 {
        nbits = 1
    }
    for i in 1..=nbits {
        res = (res.pow(2)) % p;
        delay += normal.sample(&mut rng);
        if d.bit(nbits - i) {
            res = (res * m) % p;
            let seed = res.iter_u64_digits().next().unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            delay += normal.sample(&mut rng);
        }
    }
    delay
}

struct VictimDevice {
    modulus: BigUint,
    secret: BigUint,
}

impl VictimDevice {
    pub fn new(seed: u64, keylen: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut secret = rng.gen_biguint(keylen);
        secret.set_bit(keylen - 1, true);
        VictimDevice {
            modulus: get_modulus(keylen),
            secret,
        }
    }

    pub fn sign(&self, m: &BigUint) -> f64 {
        square_and_multiply(&m, &self.secret, &self.modulus)
    }
}

struct AttackerDevice {
    modulus: BigUint,
}

impl AttackerDevice {
    pub fn new(keylen: u64) -> Self {
        AttackerDevice {
            modulus: get_modulus(keylen),
        }
    }

    pub fn sign(&self, m: &BigUint, d: &BigUint) -> f64 {
        square_and_multiply(&m, d, &self.modulus)
    }
}

fn main() {
    let mut rng = rand::rngs::OsRng;

    // Key length in bits
    let keylen = 64;
    // The more bit is keylen the more bit this value should be...
    // E.g. 64 -> 1000, 128 -> 4000, 256 -> 10000
    let variance_iters_count = 1000;

    let victim = VictimDevice::new(rng.gen(), keylen);
    let attacker = AttackerDevice::new(keylen);

    println!("secret    : {:064b}", victim.secret);
    print!("recovered : ");

    // Recovered secret
    let mut recovered = BigUint::from(0_u64);

    for _ in 0..keylen {
        let mut sum0 = 0.0;
        let mut sum0_square = 0.0;
        let mut sum1 = 0.0;
        let mut sum1_square = 0.0;

        recovered <<= 1;

        for _ in 0..variance_iters_count {
            let m = rng.gen_biguint(keylen);

            let t_vic = victim.sign(&m);

            // Attempt with i-th bit = 0
            recovered.set_bit(0, false);
            let t_att0 = attacker.sign(&m, &recovered);
            let delta0 = t_vic - t_att0;
            sum0 += delta0;
            sum0_square += delta0 * delta0;

            // Attempt with i-th bit = 1
            recovered.set_bit(0, true);
            let t_att1 = attacker.sign(&m, &recovered);
            let delta1 = t_vic - t_att1;
            sum1 += delta1;
            sum1_square += delta1 * delta1;
        }

        let exp0 = sum0 / variance_iters_count as f64;
        let var0 = (sum0_square / variance_iters_count as f64) - exp0 * exp0;

        let exp1 = sum1 / variance_iters_count as f64;
        let var1 = (sum1_square / variance_iters_count as f64) - exp1 * exp1;

        if var0 < var1 {
            recovered.set_bit(0, false);
            print!("0")
        } else {
            recovered.set_bit(0, true);
            print!("1")
        }
        io::stdout().flush().unwrap();
    }
}
