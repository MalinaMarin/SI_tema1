import socket
import helpers
from utils import PORT, KEY_SIZE


# connecting to the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', PORT)
server.connect(server_address)


#   get the k_prime and IV keys
k_prime = server.recv(16)
iv = server.recv(16)
print("A fost primita cheia K: ", k_prime.decode(), " si iv-ul ", iv.decode())


#   get the option chosen by A: ecb or cbc
option = server.recv(3).decode()
print("A a ales modul: ", option)

# get the key and decrypt it
received_key = b''
received_key += server.recv(16)
print("Am primit cheia!")
decrypted_key = helpers.decrypt_ecb(received_key, k_prime)

message = b'Confirmare - inceperea comunicarii!'

# send message - confirmation for starting the communication
server.sendall(message)
received_message = b''

while True:
    part = server.recv(16)
    received_message += part
    if len(part) < 1:
        break

if option == "ECB":
    plaintext = helpers.decrypt_ecb(received_message, decrypted_key)
    print(plaintext.decode())
else:
    plaintext2 = helpers.decrypt_cbc(received_message, decrypted_key)
    print(plaintext2.decode())
