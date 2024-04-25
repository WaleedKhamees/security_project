from Crypto.Hash import SHA1
import random
import math
from utils import large_number_to_bytes



def elgamal_private_key(prime: int) -> int:
    return random.randint(1, prime - 1)

def elgamal_public_key(a: int, Xa: int, q: int) -> int:
    return pow(a, Xa, q)


def elgamal_generate_k_prime(prime: int) -> int:
    k = random.randint(1, prime - 1)
    while math.gcd(k, prime - 1) != 1:
        k = random.randint(1, prime - 1)
    return k

def elgamal_sign(message: int, Xa: int, q: int, a: int) -> tuple:
    k = elgamal_generate_k_prime(q)
    s1 = pow(a, k, q)
    m = SHA1.new(large_number_to_bytes(message)).digest()
    m = int.from_bytes(m)

    i = (m - Xa * s1)
    j = pow(k, -1, q - 1)
    k = q - 1

    s2 = pow (i * j, 1, k)
    return s1, s2

def elgamal_verify(message: int, a: int, s1: int, s2: int, Ya: int, q: int) -> bool:
    m = SHA1.new(large_number_to_bytes(message)).digest()
    m = int.from_bytes(m)

    v1 = pow(a, m, q)
    v2 = (pow(Ya, s1, q) * pow(s1, s2, q)) % q
    return v1 == v2

