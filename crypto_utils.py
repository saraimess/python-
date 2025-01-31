from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
import os

class CryptoManager:
    def __init__(self):
        self.rsa_key_size = 2048
        self.aes_key_size = 16  # 128 bits

    def generate_rsa_keys(self):
        """Generate a new RSA key pair"""
        key = RSA.generate(self.rsa_key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def encrypt_message(self, message: str, public_key: bytes) -> dict:
        """Encrypt a message using RSA + AES hybrid encryption"""
        # Generate a random AES key
        aes_key = get_random_bytes(self.aes_key_size)
        
        # Encrypt the AES key with RSA
        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        
        # Encrypt the message with AES
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        
        # Prepare the encrypted package
        encrypted_data = {
            'encrypted_aes_key': b64encode(encrypted_aes_key).decode('utf-8'),
            'nonce': b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
        
        return encrypted_data

    def decrypt_message(self, encrypted_data: dict, private_key: bytes) -> str:
        """Decrypt a message using RSA + AES hybrid encryption"""
        # Import the private key
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        
        # Decode the encrypted package
        encrypted_aes_key = b64decode(encrypted_data['encrypted_aes_key'])
        nonce = b64decode(encrypted_data['nonce'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        tag = b64decode(encrypted_data['tag'])
        
        # Decrypt the AES key
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        
        # Decrypt the message
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
        
        return decrypted_message.decode('utf-8')

    def encrypt_file(self, file_data: bytes, public_key: bytes) -> dict:
        """Encrypt a file using RSA + AES hybrid encryption"""
        # Generate a random AES key
        aes_key = get_random_bytes(self.aes_key_size)
        
        # Encrypt the AES key with RSA
        rsa_key = RSA.import_key(public_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        
        # Encrypt the file with AES
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        
        # Prepare the encrypted package
        encrypted_data = {
            'encrypted_aes_key': b64encode(encrypted_aes_key).decode('utf-8'),
            'nonce': b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
        
        return encrypted_data

    def decrypt_file(self, encrypted_data: dict, private_key: bytes) -> bytes:
        """Decrypt a file using RSA + AES hybrid encryption"""
        # Import the private key
        rsa_key = RSA.import_key(private_key)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)
        
        # Decode the encrypted package
        encrypted_aes_key = b64decode(encrypted_data['encrypted_aes_key'])
        nonce = b64decode(encrypted_data['nonce'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        tag = b64decode(encrypted_data['tag'])
        
        # Decrypt the AES key
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        
        # Decrypt the file
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return decrypted_data 