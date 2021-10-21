import socket
import helpers
from utils import PORT, IV, K_PRIM
from Crypto.Random import get_random_bytes


def handle_choice(node_a, node_b, choice):
    if choice == '1':
        handle_ecb(node_a, node_b)
    elif choice == '2':
        handle_cbc(node_a, node_b)


def send_key(conn1, conn2, key):
    conn1.sendall(key)
    conn2.sendall(key)


def send_key_oneconn(conn_a, key):
    conn_a.sendall(key)


def handle_ecb(node_a, node_b):
    node_b.sendall("ECB".encode())
    send_key_oneconn(node_a, helpers.encrypt_key(key2))


def handle_cbc(node_a, node_b):
    node_b.sendall("CBC".encode())
    send_key_oneconn(node_a, helpers.encrypt_key(key2))


# creating the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', PORT)
sock.bind(server_address)
sock.listen(2)


# accepting 2 connections
print("Astept ca A si B sa se conecteze")
node_A, client_address = sock.accept()
node_B, client_address = sock.accept()


k_prim = K_PRIM
iv = IV

#   send K and IV to A and B

send_key(node_A, node_B, k_prim)
send_key(node_A, node_B, iv)
print("Cheia ", k_prim.decode(), " si iv-ul ", iv.decode(), "au fost trimise cu succes!")

key2 = get_random_bytes(16)

#   read  CHOICE and send the CHOICE name to B and the KEY2 to A
handle_choice(node_A, node_B, node_A.recv(1).decode())

# A sends the key to B
send_key_oneconn(node_B, node_A.recv(128))

# B sends a confirmation message to A
send_key_oneconn(node_A, node_B.recv(35))

# read a block from A and send it to B repeatedly
while True:
    block = node_A.recv(128)
    if len(block) < 1:
        break
    node_B.sendall(block)

