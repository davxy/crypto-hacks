#!/usr/bin/env python
#
# RSA Common Modulus Attack
#
# Background: https://datawok.net/posts/rsa-cipher/#common-modulus-failure
#
# Encrypt the same message `m` using the two different encryption keys but with
# the same modulus `n`:
# 
#     c1 = m^e1 mod n
#     c2 = m^e2 mod n
# 
# Let's assume that with high probability gcd(e1,e2) = 1. An attacker can thus use
# the EEA to compute x and y such that e1·x + e2·y = 1.
# 
# Finally, he can recover the plaintext:
# 
#     c1' = c1^x = m^(e1·x)
#     c2' = c2^y = m^(e2·y)
#     c1'·c2' = m^(e1·x) · m^(e2·y) = m^(e1·x + e2·y) = m
# 
# Note that if y < 0, set y = -a, with a > 0. Then c2^y = (c2^-1)^a.
# This last step requires that gcd(c2,n) = 1 in order to compute the inverse.
# If (c2,n) ≠ 1 (very unlikely) then via EEA we find a factor of n, and this
# is even better since at that point we can trivilly recover the secret key.


from math import gcd


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def main():
    # Two primes
    p = 1269137899329015734198852969175332151915502982003874425987364731216285546438096536038703243719054337
    q = 6504286590288767118032686861713724448149119312357868347142148568446447367009371975895368151336893777
    n = p*q
    phi_n = (p-1)*(q-1)

    e1 = 13
    e2 = 65537
    # Setup correctness: check secret exponent
    assert gcd(e1, phi_n) == 1, f"Not invertible secret: {e1}"
    assert gcd(e1, phi_n) == 1, f"Not invertible secret: {e2}"

    m = 12345678987654321
    print(f"[m: {m}]")
    
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    # Setup correctness: check decryption
    d1 = pow(e1, -1, phi_n)
    d2 = pow(e2, -1, phi_n)
    assert pow(c1, d1, n) == m, f"Decryption failure using first keypair"
    assert pow(c2, d2, n) == m, f"Decryption failure using second keypair"

    print(f"n: {n}")
    print(f"e1: {e1}")
    print(f"e2: {e2}")
    print(f"c1: {c1}")
    print(f"c2: {c2}")
       
    # The attack... assuming we just know e1, e2, c1, c2 and n
    
    g, x, y = egcd(e1, e2)
    # Attack requirement: 1 = e1·x + e2·y  i.e.  gcd(e1,e2) = 1
    assert g == 1, f"Secret exponents need to be coprime"

    # c1^x · c2^y = m^(e1·x) · m^(e2·y) = m^(e1·x + e2·y) 
    m_dec = (pow(c1, x, n) * pow(c2, y, n)) % n   
    assert m_dec == m, f"Unexpected failure"  
    
    # Typically y < 0. So if we are working with unsigned values...
    # c1^x · (c2^-1)^-y 
    min_y = -y
    inv_c2 = pow(c2, -1, n)
    m_dec = pow(c1, x, n) * pow(inv_c2, min_y, n) % n
    print(f"[recovered m: {m_dec}]")
    assert m_dec == m, f"Unexpected failure"  


main()

