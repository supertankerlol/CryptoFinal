import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessagingModule:
    def __init__(self):
        # Generate ECDH key pair (P-256 curve)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, recipient_pub_bytes: bytes, message: str) -> dict:
        # 1. Reconstruct recipient's public key from bytes
        recipient_pub = serialization.load_pem_public_key(recipient_pub_bytes)

        # 2. Compute Shared Secret (ECDH Key Exchange)
        # My Private Key + Recipient Public Key = Shared Secret
        shared_key = self.private_key.exchange(ec.ECDH(), recipient_pub)

        # 3. Derive encryption key using HKDF
        # Ensures the shared secret is cryptographically strong for AES
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        # 4. Encrypt using AES-256-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12) # Unique nonce for every message
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }

    def decrypt_message(self, sender_pub_bytes: bytes, encrypted_data: dict) -> str:
        """
        Decrypt a message received from a sender.
        """
        # 1. Reconstruct sender's public key
        sender_pub = serialization.load_pem_public_key(sender_pub_bytes)

        # 2. ECDH Magic: My Private Key + Sender's Public Key = Same Shared Secret
        shared_key = self.private_key.exchange(ec.ECDH(), sender_pub)

        # 3. Derive the exact same encryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        # 4. Decrypt using AES-GCM
        aesgcm = AESGCM(derived_key)

        # Convert HEX strings back to bytes
        nonce = bytes.fromhex(encrypted_data['nonce'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')