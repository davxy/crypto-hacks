//! Simple Shanks Algorithm implementation.
//!
//! Shanks algorithm, also known as *Baby-Step Giant-Step*, is a meet-in-the-middle
//! algorithm for computing the discrete logarithm of an element in a finite
//! abelian group.
//!
//! This simple implementation is not supposed to target groups with order bigger
//! than how much an `HashMap` memory table can handle.
//!
//! Further optimizations are possible by partitioning the table construction
//! and lookup tasks on multiple execution threads (e.g. via `rayon`).
//!
//! Some background: https://datawok.net/posts/discrete-logarithm/#shanks-algorithm

use num::ToPrimitive;
use num_bigint::{BigUint, ToBigUint};
use std::collections::HashMap;

/// Shanks algorithm.
///
/// Params:
/// * `n`: group prime modulus
/// * `g`: group generator (order n-1)
/// * `h`: value for which we want to compute the discrete log (i.e. g^x = h)
///
/// h = g^x = g^(m·i + j), with m = ⌈√n⌉.
///
/// 1. Compute g^(jx_b) for 0 ≤ x_b < m
/// 2. Compute h·g^(-m·x_g) for 0 ≤ x_g < m
/// 3. Check for a collision
pub fn shanks(n: BigUint, g: BigUint, h: BigUint) -> Option<BigUint> {
    let mut table = HashMap::new();
    let m = n.sqrt().to_usize().expect("Can't convert √{n} to f64") + 1;
    let mut e = BigUint::from(1_u8);

    // Compute and store g^j mod n
    for j in 0..m {
        table.insert(e.clone(), j);
        e *= &g;
        e %= &n;
    }

    // g^-m = g^(φ(n)-m) = g^(n-1-m) (mod n)
    let factor = g.modpow(&(&n - 1_u8 - m), &n);

    let mut e = h;
    for i in 0..m {
        // Check if h·g^(-m·i) = g^j
        if let Some(j) = table.get(&e) {
            return (i * m + j).to_biguint();
        }
        // In practice this is: e = h·g^(-m*i)
        e *= &factor;
        e %= &n;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test() {
        let n = BigUint::from(433_u32);
        let g = BigUint::from(5_u32);
        let h = BigUint::from(71_u32);

        assert_eq!(shanks(n, g, h), Some(BigUint::from(103_u32)));
    }
}
