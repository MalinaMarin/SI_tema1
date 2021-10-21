import socket
import helpers
from utils import PORT


def handle_mode(connection, option, key):
    if option == "1":
        send_encrypted_ecb(connection, key)
    if option == "2":
        send_encrypted_cbc(connection, key)


def send_encrypted_ecb(connection, key):
    with open('plaintext.txt') as f:
        block = f.read()
        encrypted_block = helpers.encrypt_ecb(block.encode(), key)
        connection.sendall(encrypted_block)


def send_encrypted_cbc(connection, key):
    with open('plaintext.txt') as f:
        block = f.read()
        encrypted_block = helpers.encrypt_cbc(block.encode(), key)
        connection.sendall(encrypted_block)


# connecting to the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', PORT)
server.connect(server_address)


# get K_prime and IV
k_prime = server.recv(16)
iv = server.recv(16)
print("Au fost primite:  cheia K: ", k_prime.decode(), " si vectorul de initializare: ", iv.decode())


# send the option
choice = input("Alege modul de criptare: \n1. ECB\n2. CBC\n")
server.sendall(choice.encode())

#  receive K and decrypt it using K
received_key = server.recv(16)
server.sendall(received_key)
print("Am trimis cheia catre B cu succes!")
decrypted_key = helpers.decrypt_ecb(received_key, k_prime)

message = server.recv(35)
print(message.decode())

#  send the data with the option ecb / cbc
handle_mode(server, choice, decrypted_key)
