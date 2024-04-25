from utils import read_Public_Parameters
from diffie_hellman import diffie_hellman_genPriKey, diffie_hellman_genPubKey
from elgamal import elgamal_private_key, elgamal_public_key, elgamal_sign


def generate_keys(): 
    diffie_hellman_q, diffie_hellman_a = read_Public_Parameters("public_parameter_diffie.txt")
    elgamal_q, elgamal_a = read_Public_Parameters("public_parameter_elgamal.txt")

    diffie_hellman_Xa = diffie_hellman_genPriKey(diffie_hellman_q)
    diffie_hellman_Ya = diffie_hellman_genPubKey(diffie_hellman_q, diffie_hellman_a, diffie_hellman_Xa)

    elgamal_Xa = elgamal_private_key(elgamal_q)
    elgamal_Ya = elgamal_public_key(elgamal_a, elgamal_Xa, elgamal_q)

    s1, s2  = elgamal_sign(diffie_hellman_Ya, elgamal_Xa, elgamal_q, elgamal_a)

    return diffie_hellman_Xa, diffie_hellman_Ya, elgamal_Xa, elgamal_Ya, elgamal_q, elgamal_a, s1, s2


