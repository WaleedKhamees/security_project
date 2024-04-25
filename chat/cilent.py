import socket
import threading
from key_exchange import generate_keys
from elgamal import elgamal_verify
from utils import large_number_to_bytes, Send_Message, Receive_Message
from diffie_hellman import diffie_hellman_calSharedKey
from Crypto.Hash import SHA256


IP = "localhost"
PORT = 1234

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((IP, PORT))


try:
    diffie_hellman_Xb, diffie_hellman_Yb, diffie_hellman_q, elgamal_Xb, elgamal_Yb, elgamal_q, elgamal_a, s1, s2 = generate_keys()


    # sending and receiving elgamal_Ya
    # print("elgamal_Ya: ", elgamal_Yb)
    client.send(large_number_to_bytes(elgamal_Yb))

    server_elgamal_Ya = int.from_bytes(client.recv(512))
    # print("server_elgamal_Yb: ", server_elgamal_Ya)


    # receiving diffie_hellman_Ya, s1, s2
    server_diffie_Ya = int.from_bytes(client.recv(512))
    client.send("ACK".encode())
    server_s1 = int.from_bytes(client.recv(512))
    client.send("ACK".encode())
    server_s2 = int.from_bytes(client.recv(512))
    client.send("ACK".encode())

    # print("server_diffie_Ya: ", server_diffie_Ya)
    # print("server_s1: ", server_s1)
    # print("server_s2: ", server_s2)


    is_verified = elgamal_verify(
        server_diffie_Ya, elgamal_a,  server_s1, server_s2, server_elgamal_Ya, elgamal_q)

    if is_verified:
        print("Verified")
    else:
        print("Not Verified")
        client.close()
        exit(1)


    # sending diffie_hellman_Ya, s1, s2
    client.send(large_number_to_bytes(diffie_hellman_Yb))
    buffer = client.recv(512)
    client.send(large_number_to_bytes(s2))
    buffer = client.recv(512)
    client.send(large_number_to_bytes(s1))
    buffer = client.recv(512)

    # print("client_diffie_Yb: ", diffie_hellman_Yb)
    # print("client_s2: ", s2)
    # print("client_s1: ", s1)

    sharedKey = diffie_hellman_calSharedKey(
        server_diffie_Ya, diffie_hellman_Xb, diffie_hellman_q)

    key = SHA256.new(large_number_to_bytes(sharedKey)).digest()

    print("Key: ", key)
    threading.Thread(target=Send_Message, args=(client, key)).start()
    threading.Thread(target=Receive_Message, args=(client, key)).start()
except KeyboardInterrupt: 
    client.close()
