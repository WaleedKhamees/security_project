import socket
import threading
from key_exchange import generate_keys
from utils import large_number_to_bytes, Send_Message, Receive_Message
from elgamal import elgamal_verify
from diffie_hellman import diffie_hellman_calSharedKey
from Crypto.Hash import SHA256


IP = "localhost"
PORT = 1234



server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IP, PORT))
server.listen()
try:

    client, _ = server.accept()

    diffie_hellman_Xa, diffie_hellman_Ya, diffie_hellman_q, elgamal_Xa, elgamal_Ya, elgamal_q, elgamal_a, s1, s2 = generate_keys()


    # sending and receiving elgamal_Ya

    # print("elgamal_Ya: ", elgamal_Ya)
    client_elgamal_Yb = int.from_bytes(client.recv(512))

    client.send(large_number_to_bytes(elgamal_Ya))
    # print("client_elgamal_Yb: ", client_elgamal_Yb)


    # sending diffie_hellman_Ya, s1, s2
    client.send(large_number_to_bytes(diffie_hellman_Ya))
    buffer = client.recv(512)
    client.send(large_number_to_bytes(s1))
    buffer = client.recv(512)
    client.send(large_number_to_bytes(s2))
    buffer = client.recv(512)

    # print("client_diffie_Yb: ", diffie_hellman_Ya)
    # print("client_s2: ", s2)
    # print("client_s1: ", s1)

    # receiving diffie_hellman_Ya, s1, s2
    client_diffie_Yb = int.from_bytes(client.recv(512))
    client.send("ACK".encode())
    client_s2 = int.from_bytes(client.recv(512))
    client.send("ACK".encode())
    client_s1 = int.from_bytes(client.recv(512))
    client.send("ACK".encode())

    # print("client_diffie_Yb: ", client_diffie_Yb)
    # print("client_s2: ", client_s2)
    # print("client_s1: ", client_s1)


    is_verified = elgamal_verify(
        client_diffie_Yb, elgamal_a,  client_s1, client_s2, client_elgamal_Yb, elgamal_q)


    if is_verified:
        print("Verified")
    else:
        print("Not Verified")
        client.close()
        exit(1)

    sharedKey = diffie_hellman_calSharedKey(
        client_diffie_Yb, diffie_hellman_Xa, diffie_hellman_q)

    key = SHA256.new(large_number_to_bytes(sharedKey)).digest()



    print("Key: ", key)
    threading.Thread(target=Send_Message, args=(client, key)).start()
    threading.Thread(target=Receive_Message, args=(client, key)).start()
except KeyboardInterrupt: 
    server.close()
    exit(0)


