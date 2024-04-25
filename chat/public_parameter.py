
from Crypto.Util import number
from utils import *




prime_number_elgamal = number.getPrime(256)
alpha_elgamal = get_primitive_root(prime_number_elgamal)

prime_number_diffie = number.getPrime(256)
alpha_diffie = get_primitive_root(prime_number_diffie)


with open("public_parameter_elgamal.txt", "w") as f: 
    f.write(f"{prime_number_elgamal}\n{alpha_elgamal}")

with open("public_parameter_diffie.txt", "w") as f: 
    f.write(f"{prime_number_diffie}\n{alpha_diffie}")
