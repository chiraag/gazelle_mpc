import primefac
# import yafu
import numpy as np
import random

factor_silent = True

def round(x):
  return int(np.round(x))

def floor(x):
  return int(np.floor(x))

def ceil(x):
  return int(np.ceil(x))

def log2(x):
  return np.log2(x*1.0)

def factor(n):
  if log2(n) > 128:
    return yafu.factor(n, silent=factor_silent)
  else:
    return primefac.factorint(n)

def prime_form(bits, i, m):
  # Outputs p (may not be prime) s.t. p-1 | m
  return 2**bits - pow(2, bits, m) + i*m + 1

def get_primes(bits, m, max_attempt=10000):
  # Outputs primes s.t. p-1 | m
  primes = {}
  for i in range(max_attempt):
    p = prime_form(bits, i, m)
    if primefac._primefac.isprime(p):
      primes[p] = i
  return primes

def primitive_root(q, factors=None):
  if factors == None:
    factors = factor(q-1)
  g = 0
  while True:
    g = random.randint(0, q-1) # randint limits are inclusive
    if not primefac._primefac.gcd(g, q) == 1:
      continue

    is_primtive = True
    for p in factors:
      co_factor = (q-1)//p
      if pow(g, co_factor, q) == 1:
        is_primtive = False
        break

    if is_primtive:
      break
  return g

def root_of_unity(q, m):
  assert((q-1) % m == 0)
  g = primitive_root(q)
  z = pow(g, (q-1)//m, q)
  assert(pow(z, m, q) == 1) # Necessary, sufficient if g is primitive
  return z

def is_mult_generator(g, m, factors=None):
  if factors == None:
    factors = factor(m-1)
  for p in factors:
    co_factor = (m-1)//p
    if pow(g, co_factor, m) == 1:
      return False
  return True
