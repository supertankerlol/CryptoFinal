import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessagingModule:
    def __init__(self):
        # Генерация пары ключей ECDH (P-256) [cite: 65]
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, recipient_pub_bytes: bytes, message: str) -> dict:
        # 1. Восстановление публичного ключа получателя
        recipient_pub = serialization.load_pem_public_key(recipient_pub_bytes)

        # 2. Получение общего секрета (ECDH Shared Secret) [cite: 84]
        shared_key = self.private_key.exchange(ec.ECDH(), recipient_pub)

        # 3. Деривация ключа шифрования через HKDF [cite: 66]
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        # 4. Шифрование AES-256-GCM [cite: 68]
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12) # Уникальный nonce [cite: 69]
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }