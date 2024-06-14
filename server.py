import socket
import threading
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets
import datetime

# Generate server's RSA key pair
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

clients = []
# keeps track of connected client sockets

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)

def handle_client(client_socket):
    try:
        # Log client connection
        log_data = {
            'timestamp': str(datetime.datetime.now()),
            'event': 'Client connected',
            'client_address': client_socket.getpeername()
        }
        logging.info(json.dumps(log_data))

        client_public_key_pem = client_socket.recv(4096)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        
        server_public_key_pem = server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        client_socket.sendall(server_public_key_pem)
        
        shared_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=secrets.token_bytes(32), info=b'handshake data').derive(os.urandom(32))
        
        encrypted_shared_key = client_public_key.encrypt(
            shared_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        client_socket.sendall(encrypted_shared_key)

        while True:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break

            cipher = Cipher(algorithms.AES(shared_key), modes.CFB(shared_key[:16]))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

            # Log received message
            log_data = {
                'timestamp': str(datetime.datetime.now()),
                'event': 'Message received',
                'client_address': client_socket.getpeername(),
                'message': decrypted_message.decode()
            }
            logging.info(json.dumps(log_data))

            print(f"Received: {decrypted_message.decode()}")

            for client in clients:
                if client != client_socket:
                    client.sendall(encrypted_message)
    except Exception as e:
        # Log error
        log_data = {
            'timestamp': str(datetime.datetime.now()),
            'event': 'Error',
            'error_message': str(e)
        }
        logging.error(json.dumps(log_data))
    finally:
        client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 9999))
server.listen(5)
print("Server listening on port 9999")

while True:
    client_socket, addr = server.accept()
    clients.append(client_socket)
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()