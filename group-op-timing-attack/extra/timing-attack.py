#!/bin/python
#
# Timing attack simulation for a device implementing some form
# of group operation not in constant time.
#
# For example, given a message `m` and a secret `d`, the module can simulate:
# - m^d mod n using square and multiply
# - d·m mod n using double and add
#
# The secret is recovered using the
# [variance difference strategy](https://datawok.net/posts/timing-attack).
#
# It is a probabilistic attack in nature, so you may not be successfull on the
# first run.
# 
# The execution times of group operations are not fixed but vary with the value
# of `m`. If `m` is chosen randomly, these times follow a Gaussian distribution
# with a configurable mean μ and standard deviation σ (with default μ = 1000
# and σ = 50).

import random
import numpy as np
import sys

# Primes to be used to reduce the group operation result
primes = {
    8: 61,
    16: 53759,
    32: 2675797811,
    64: 8642890157798231327,
    128: 249018405283997733407297959207515566297,
}

class Device():
    def __init__(self, keylen = 64, mu = 1000, sigma = 50):
        self.p = primes[keylen]
        self.keylen = keylen
        self.mu = mu
        self.sigma = sigma
        # Choose the group operation
        self.group_op = self.double_and_add
        # self.group_op = self.square_and_mul

    def double_and_add(self, m, d):
        '''
        Returns the execution time of the double and add algorithm
        '''
        res = 1
        delay = 0
        np.random.seed(m % 2**32)
        for i in range(len(d)):
            res = (res * 2) % self.p
            delay = delay + np.random.normal(self.mu, self.sigma)
            if d[i] == 1:
                res = (res + m) % self.p
                np.random.seed(res % 2**32)
                delay = delay + np.random.normal(self.mu, self.sigma)
        return delay       

    def square_and_mul(self, m, d):
        '''
        Returns the execution time of the double and add algorithm
        '''
        res = 1
        delay = 0
        np.random.seed(m % 2**32)
        for i in range(len(d)):
            res = (res * res) % self.p
            delay = delay + np.random.normal(self.mu, self.sigma)
            if d[i] == 1:
                res = (res * m) % self.p
                np.random.seed(res % 2**32)
                delay = delay + np.random.normal(self.mu, self.sigma)
        return delay       
 

class AttackerDevice(Device):
    def sign(self, c, d):
        return self.group_op(c, d)   


class VictimDevice(Device):
    # Default seed used to construct the secret key.
    built_in_seed = 123312834

    def __init__(self, keylen = 64, mu = 1000, sigma = 50, secret_seed = built_in_seed):
        super().__init__(keylen, mu, sigma)
        np.random.seed(secret_seed)
        self.secret = [1] + [int(np.random.rand() <= 0.5) for i in range(self.keylen - 1)]
        print(self.secret)

    def sign(self, c):
        return self.group_op(c, self.secret)

    def check(self, d):
        f = sum([int(self.secret[i] == d[i]) for i in range(self.keylen)])/self.keylen
        if (f < 0.75):
            print('Less than 75% of key bits recovered.')
        elif (f < 1):
            print('At least 75%, but less than 100% of key bits recovered.')
        else:
            print('100% of key bits recovered.')


def main():
    # Iterations to compute the variance
    N = 4000
    # Secret key length
    keylen = 64
    # Secret key seed
    seed = random.randint(1, 4294967295)
    # Artifical delay params
    mu = 1000
    sigma = 50

    # Devices construction
    victim = VictimDevice(keylen, mu, sigma, secret_seed = seed)
    attacker = AttackerDevice(keylen, mu, sigma)

    # List which saves the disclosed secret exponent bits (left to right)
    print("Recovering {}-bit secret".format(attacker.keylen))
    recovered = []
    for i in range(0, keylen):
        sum0 = 0
        sum0_square = 0
        sum1 = 0
        sum1_square = 0
        recovered.append(0)
        for j in range (N):
            c = random.randint(1, 2**keylen)
            # Measure the time taken by the victim
            t_vic = victim.sign(c)
            # Try with i-th bit set to 0
            recovered[i] = 0
            t_att0 = attacker.sign(c, recovered)
            sum0_square = sum0_square + (t_vic-t_att0)**2
            sum0 = sum0 + (t_vic - t_att0)
            # Try with i-th bit set to 1
            recovered[i] = 1
            t_att1 = attacker.sign(c, recovered)
            sum1_square = sum1_square + (t_vic-t_att1)**2
            sum1 = sum1 + (t_vic - t_att1)
        # The chosen bit value is the one which gives a smaller variance
        var0 = sum0_square/N - (sum0/N)**2
        var1 = sum1_square/N - (sum1/N)**2
        if var0 < var1:
            recovered[i] = 0
        else:
            recovered[i] = 1
        print(recovered[i], end = "")
        sys.stdout.flush()
    print("")

    victim.check(recovered)
    print(recovered)
    
main()
