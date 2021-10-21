
from Crypto.Cipher import AES
import utils


def encrypt_key(key):
    cipher = AES.new(utils.K_PRIM, AES.MODE_ECB)
    return cipher.encrypt(key)


def decrypt_key(encrypted_key):
    cipher = AES.new(utils.K_PRIM, AES.MODE_ECB)
    return cipher.decrypt(encrypted_key)


def pad(message):
    new = message
    while len(new) % 16:
        new += b'!'
    return new


def unpad(message):
    for i in message[-16:]:
        if i == '!':
            message = message[:-1]
    message = message[:-1]
    return message


def xor_on_bytes(c, d):
    return bytes(a ^ b for (a, b) in zip(c, d))


def encrypt_ecb(message, key):
    ciphertext = b""
    cipher = AES.new(key, AES.MODE_ECB)
    message = pad(message)
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    for block in blocks:
        ciphertext += cipher.encrypt(block)
    return ciphertext


def decrypt_ecb(ciphertext, key):
    plaintext = b""
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    for block in blocks:
        plaintext += cipher.decrypt(block)
    return plaintext


def encrypt_cbc(message, key):
    message = pad(message)
    current_block = bytes(message)[:16]
    iv = utils.IV
    ciphertext = b''
    while len(message) > 0:
        encrypted_block = AES.new(key, AES.MODE_ECB).encrypt(xor_on_bytes(iv, current_block))
        ciphertext += encrypted_block
        message = message[16:]
        current_block = bytes(message[:16])
        iv = encrypted_block
    return ciphertext


def decrypt_cbc(message, key):
    current_block = message[:16]
    iv = utils.IV
    plaintext = b''
    while len(message) > 0:
        plain_text = xor_on_bytes(iv, AES.new(key, AES.MODE_ECB).decrypt(current_block))
        plaintext += plain_text
        message = message[16:]
        iv = current_block
        current_block = message[:16]
    return unpad(plaintext)

