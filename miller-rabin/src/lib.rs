//! Miller-Rabin primality test using `num-bigint` crate.
//!
//! Some background: https://datawok.net/posts/random-primes

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;

const MILLER_RABIN_MAX_ITER: usize = 8;
const PRIME_GEN_MAX_ATTEMPTS: usize = 5000;

const SMALL_PRIMES: [u16; 175] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
];

use rayon::prelude::*;

fn miller_rabin_test(n: &BigUint, limit: usize) -> bool {
    let one = BigUint::one();
    let two = &one + &one;
    let n_minus_one = n - &one;

    // d becomes an even number
    let mut s = BigUint::zero();
    let mut d = n_minus_one.clone();
    while d.is_even() {
        s += &one;
        d >>= 1;
    }

    let predicate = |_| {
        let x = OsRng.gen_biguint_range(&two, &n_minus_one);

        let mut x = x.modpow(&d, &n);
        if x == one || x == n_minus_one {
            return true;
        }

        let mut count = BigUint::one();
        while count < s {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                return true;
            }
            count += 1u8;
        }
        false
    };

    (0..limit).into_par_iter().all(predicate)
}

/// Returns `true` if probably prime, `false` otherwise.
pub fn is_prime(n: &BigUint) -> bool {
    let zero = BigUint::zero();
    let one = BigUint::one();

    if n == &zero {
        return false;
    }
    if n == &one {
        return true;
    }

    // Check if is a small prime multiple first
    for p in SMALL_PRIMES.iter() {
        let d = BigUint::from(*p);
        if n % &d == zero {
            // At this point n is a small prime or a multiple of a small prime.
            return n == &d;
        }
    }

    // Miller-Rabin
    if !miller_rabin_test(n, MILLER_RABIN_MAX_ITER) {
        return false;
    }

    true
}

/// Find a prime number with the given number of `bits`.
///
/// Returns the found number.
pub fn prime_num(bits: usize, attempts: Option<usize>) -> Option<BigUint> {
    let attempts = attempts.unwrap_or(PRIME_GEN_MAX_ATTEMPTS);

    (0..attempts).into_par_iter().find_map_any(|_| {
        let mut n = OsRng.gen_biguint(bits as u64);
        if n.is_even() {
            n = n + BigUint::one();
        }
        is_prime(&n).then_some(n)
    })
}

/// Find a prime number with the given number of `bits`.
///
/// Returns the found number and the required number of attempts to find it.
/// This is a non parallel version of `prime_num` and is mostly provided to
/// get the number of required attempts (e.g. to compute an average to compare
/// with the theoretical expected value `bits·log(2)/2`).  
pub fn prime_num_serial(bits: usize, attempts: Option<usize>) -> Option<(BigUint, usize)> {
    let attempts = attempts.unwrap_or(PRIME_GEN_MAX_ATTEMPTS);

    (0..attempts).into_iter().find_map(|i| {
        let mut n = OsRng.gen_biguint(bits as u64);
        if n.is_even() {
            n = n + BigUint::one();
        }
        if is_prime(&n) {
            Some((n, i))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_big_prime() {
        let n = prime_num(4096, None);
        println!("{:?}", n);

        assert!(n.is_some());
    }

    #[test]
    fn small_primes_test_works() {
        let n = BigUint::from(0_u32);
        assert!(!is_prime(&n));

        let n = BigUint::from(1_u32);
        assert!(is_prime(&n));

        let n = BigUint::from(2_u32);
        assert!(is_prime(&n));

        let n = BigUint::from(17791_u32);
        assert!(is_prime(&n));

        let n = BigUint::from(17791 * 17839 * 17851_u64);
        assert!(!is_prime(&n));
    }

    #[test]
    fn miller_rabin_test_works() {
        let p = BigUint::parse_bytes(
            b"1269137899329015734198852969175332151915502982003874425987364731216285546438096536038703243719054337",
            10,
        ).unwrap();
        assert!(is_prime(&p));

        let q = BigUint::parse_bytes(
            b"6504286590288767118032686861713724448149119312357868347142148568446447367009371975895368151336893777",
            10,
        ).unwrap();
        assert!(is_prime(&q));

        let pq = p * q;
        assert!(!is_prime(&pq));
    }
}
