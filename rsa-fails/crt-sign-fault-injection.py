#!/usr/bin/env python
#
# (Schoolbook) RSA with CRT - Signature fault injection attack 
#
# Given an implementation of RSA digital signature that uses the CRT
# 
#     m^d ≡ Sp (mod p)
#     m^d ≡ Sq (mod q)
# 
#     S = CRT(Sp, Sq) = Sp·q·(q^(-1) mod p)) + Sq·p·(p^(-1) mod q)) mod n
# 
# If an attacker is able to make the victim recompute the signature but this time
# introducing an error during the computation of `Sq`, then he can recover `p`
# and `q`.
# 
# Let's say he can replace `Sq` with an arbitrary `R ∈ Zq*`, then:
# 
#     S' = CRT(Sp, R) = Sp·q·(q^(-1) mod p)) + R·p·(p^(-1) mod q)) mod n
# 
#     S - S' = Sq·p·(p^(-1) mod q)) - R·p·(p^(-1) mod q)) mod n
#            = (Sq - R)·p·(p^(-1) mod q)) mod n
# 
# For sure:
# 
# - `q∤p` because are both primes
# - `q∤[p^(-1) mod q]` because is not zero and less than `q`
# - `q∤(Sq - R)` because is not zero and Sq and R are both in `Zq*`,
#    Thus `q` doesn't divide their abs difference `|Sq - R|` 
#    and then `q` doesn't divide it `Sq - R` neither.
# 
# Then `gcd(S - S', n = p·q) = p`  and  `q = n / p` 
# 
# Note that `gcd(k mod n, n) = gcd(k, n)`  (for Euclid's algorithm)
# Thus for `gcd(S - S', n)` we ignored that `S-S'` was reduced modulo n.


from math import gcd


# Setup values
p = 1269137899329015734198852969175332151915502982003874425987364731216285546438096536038703243719054337
q = 6504286590288767118032686861713724448149119312357868347142148568446447367009371975895368151336893777
n = p*q
phi_n = (p-1)*(q-1)
e = 65537
d = pow(e, -1, phi_n)

m = 1234519048532148324

# Sign the message (CRT)
s1 = pow(m, d, p)
s2 = pow(m, d, q)
s = (s1 * q * pow(q, -1, p) + s2 * p * pow(p, -1, q)) % n

# Assert correctness of CRT signature (just in case...)
assert s == pow(m, d, n), f"Something went wrong, are p and q coprimes?"

# Let's simulate a fault during signature computation of s2 value
r = 91238102380912903
assert gcd(r, q) == 1, f"The random fault should be coprime with q"
f = (s1 * q * pow(q, -1, p) + r * p * pow(p, -1, q)) % n

# The attacker receives both `s` and `f`.
# He can easily recover `p` and `q` (and thus the secret `d`)
p1 = gcd((s - f), n)
q1 = n // p1
assert p1 * q1 == n, f"Something went wrong, retry with a different r"
