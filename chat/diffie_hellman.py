import random

def diffie_hellman_genPriKey(q):
    return random.randint(1, q-1)
    
def diffie_hellman_genPubKey(q, a, Xa):
    Ya = pow(a, Xa, q)
    return Ya

def diffie_hellman_calSharedKey(Yb, Xa, q):
    return pow(Yb, Xa, q)