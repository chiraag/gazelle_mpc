from __future__ import print_function

import primefac
import numpy as np
import nbtheory

def get_p(pbits=20, m=4096, num_primes=10):
    r = pow(2, pbits, m)
    primes = []
    for k in range(2**pbits//m):
        p = 2**pbits - r + m*k + 1
        if primefac._primefac.isprime(p):
            primes.append(p)
        if len(primes) == num_primes:
            break
    return primes

def get_q(qbits=60, pbits=20, n=2048, r=1, num_primes=10):
    m = 2*n
    qbase = 2**qbits
    min_delta = qbase
    primes_p = get_p(pbits, m, num_primes)
    q, p = (None, None)
    # print primes_p
    for p_curr in primes_p:
        m_inv = primefac._primefac.modinv(m, p_curr)
        p_inv = primefac._primefac.modinv(p_curr, m)
        delta_p = (2**qbits - r) % p_curr
        delta = (-1*p_inv*p_curr + delta_p*m_inv*m) % (m*p_curr)
        q_curr = 2**qbits - delta
        if primefac._primefac.isprime(q_curr):
            if delta < min_delta:
                min_delta = delta
                q, p = q_curr, p_curr
    if q is not None:
        assert(p % m == 1), p % m
        assert((q - r) % p == 0), q % p
        assert(q % m == 1), q % m
        assert(primefac._primefac.isprime(q))
        assert(primefac._primefac.isprime(p))
    # print "delta", np.log2(delta)
    if np.log2(min_delta) < (qbits-6)/2:
        return q, p
    else:
        return None, None

n = 2048
prime_table = {}
for pbits in range(18, 21):
    print("Searching for pbits = %d" % pbits)
    for qbits in [60, 61, 59, 62, 58, 63]:
        for r in [1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 7, -7]:
            q, p =  get_q(qbits, pbits, n, r, 16384)
            if q is not None:
                prime_table[pbits] = (q, p)
                print("Found")
                break
        if pbits in prime_table:
            break

for pbits in prime_table:
    q, p = prime_table[pbits]
    zq = nbtheory.root_of_unity(q, n*2)
    zp = nbtheory.root_of_unity(p, n*2)
    print(q, p, np.log2(q), np.log2(p), q % p, zq, zp)
