import socket
import json
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate client's RSA key pair
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 9999))

# Send client's public key to server
client_public_key_pem = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
client.sendall(client_public_key_pem)

# Receive server's public key
server_public_key_pem = client.recv(4096)
server_public_key = serialization.load_pem_public_key(server_public_key_pem)

# Receive and decrypt shared key
encrypted_shared_key = client.recv(4096)
shared_key = client_private_key.decrypt(
    encrypted_shared_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

def receive_messages():
    while True:
        encrypted_message = client.recv(4096)
        if not encrypted_message:
            break

        # Decrypt the message
        cipher = Cipher(algorithms.AES(shared_key), modes.CFB(shared_key[:16]))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

        print(f"Received: {decrypted_message.decode()}")

receive_thread = threading.Thread(target=receive_messages)
receive_thread.start()

while True:
    message = input("Enter message: ")
    # Encrypt the message
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(shared_key[:16]))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    
    client.sendall(encrypted_message)
