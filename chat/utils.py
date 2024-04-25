import math
from sympy import isprime, primitive_root


def read_Public_Parameters(File_Path):
    with open(File_Path, 'r') as file:
        q = int(file.readline())
        a = int(file.readline())
    return q, a

def large_number_to_bytes(num):
    num_bytes = math.ceil(num.bit_length() / 8)  # Calculate the number of bytes needed
    num_bytes = max(num_bytes, 1)  # Ensure at least one byte is used

    # Convert the number to bytes
    byte_chunks = []
    for _ in range(num_bytes):
        byte = num & 0xFF  # Extract the least significant byte
        byte_chunks.append(byte.to_bytes(1, 'big'))  # Append the byte to the list
        num >>= 8  # Shift the number right by 8 bits

    # Reverse the order of byte_chunks and join them to get the byte representation
    byte_representation = b''.join(reversed(byte_chunks))
    return byte_representation

def get_primitive_root(prime: int) -> int:
    if not isprime(prime):
        raise ValueError("The number is not prime")
    return primitive_root(prime)

def pad_to_n_bits(number, bits):
    binary_str = bin(number)[2:]

    padding_length = bits - len(binary_str)

    padded_binary_str = '0' * padding_length + binary_str

    return int(padded_binary_str, 2)


