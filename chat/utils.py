import math
from sympy import isprime, primitive_root
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def read_Public_Parameters(File_Path):
    with open(File_Path, 'r') as file:
        q = int(file.readline())
        a = int(file.readline())
    return q, a


def large_number_to_bytes(num):
    # Calculate the number of bytes needed
    num_bytes = math.ceil(num.bit_length() / 8)
    num_bytes = max(num_bytes, 1)  # Ensure at least one byte is used

    # Convert the number to bytes
    byte_chunks = []
    for _ in range(num_bytes):
        byte = num & 0xFF  # Extract the least significant byte
        # Append the byte to the list
        byte_chunks.append(byte.to_bytes(1, 'big'))
        num >>= 8  # Shift the number right by 8 bits

    # Reverse the order of byte_chunks and join them to get the byte representation
    byte_representation = b''.join(reversed(byte_chunks))
    return byte_representation


def get_primitive_root(prime: int) -> int:
    if not isprime(prime):
        raise ValueError("The number is not prime")
    return primitive_root(prime)


def pad(byte_array:bytearray):
    block_size = 256
    pad_len = block_size - len(byte_array) % block_size
    return byte_array + (bytes([pad_len]) * pad_len)

def unpad(byte_array:bytearray):
    return byte_array[:-ord(byte_array[-1:])]

def encrypt(message:str, key)->str:
        byte_array = message.encode("UTF-8")
        padded = pad(byte_array)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode('utf-8')

def decrypt(message:str, key)->str:
    byte_array = base64.b64decode(message)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(byte_array)
    unpadded = unpad(decrypted)
    return unpadded.decode('utf-8')

        

def Send_Message(client, key):
    while True:
        message = input("> ")
        if len(message) == 0:
            continue
        encrypted_message = encrypt(message, key)
        client.send(encrypted_message.encode())
        client.recv(512)  

def Receive_Message(client, key):
    while True:
        cipher = client.recv(512)
        client.send("ACK".encode()) 

        decrypted_message = decrypt(cipher, key)
        print(f"\n# {decrypted_message}")
        print("> ", end="")

