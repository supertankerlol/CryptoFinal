import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization

class FileEncryptionModule:
    def __init__(self):
        self.chunk_size = 64 * 1024

    def _derive_master_key(self, password: str, salt: bytes) -> bytes:
        """Derive master key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, file_path: str, password: str) -> str:
        """
        Encrypts a file.
        Returns the path to the encrypted file.
        File format: [Salt(16)] [Nonce(12)] [Encrypted_FEK] [Ciphertext...]
        """
        # 1. Prepare keys
        salt = os.urandom(16)
        master_key = self._derive_master_key(password, salt)

        # File Encryption Key (FEK) - random key for the file itself
        fek = AESGCM.generate_key(bit_length=256)

        # Encrypt FEK using the master key
        aesgcm_master = AESGCM(master_key)
        fek_nonce = os.urandom(12)
        encrypted_fek = aesgcm_master.encrypt(fek_nonce, fek, None)

        # 2. Prepare content encryption
        aesgcm_file = AESGCM(fek)
        file_nonce = os.urandom(12)

        output_path = file_path + ".enc"

        # Hash of the original file for integrity verification
        file_hash = hashlib.sha256()

        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write header
            f_out.write(salt)              # 16 bytes
            f_out.write(fek_nonce)         # 12 bytes
            f_out.write(encrypted_fek)     # len(fek) + 16 tag
            f_out.write(file_nonce)        # 12 bytes

            # Stream encryption is not directly supported in AES-GCM (one-shot),
            # but for a student project, it is acceptable to load the whole file
            # or encrypt in chunks (with limitations).
            # For GCM, it is safer to encrypt the entire block.
            # For huge files, AES-CTR + HMAC is typically used.
            # Here we load content for GCM (as in lecture examples).
            data = f_in.read()
            file_hash.update(data)

            ciphertext = aesgcm_file.encrypt(file_nonce, data, None)
            f_out.write(ciphertext)

        return output_path, file_hash.hexdigest()

    def decrypt_file(self, enc_file_path: str, password: str) -> str:
        with open(enc_file_path, 'rb') as f:
            # Read metadata
            salt = f.read(16)
            fek_nonce = f.read(12)
            # Key length 32 bytes + 16 bytes tag = 48 bytes
            encrypted_fek = f.read(48)
            file_nonce = f.read(12)
            ciphertext = f.read()

        # 1. Reconstruct master key
        master_key = self._derive_master_key(password, salt)

        try:
            # 2. Decrypt FEK
            aesgcm_master = AESGCM(master_key)
            fek = aesgcm_master.decrypt(fek_nonce, encrypted_fek, None)

            # 3. Decrypt content
            aesgcm_file = AESGCM(fek)
            plaintext = aesgcm_file.decrypt(file_nonce, ciphertext, None)

            # Save decrypted file
            out_path = enc_file_path.replace(".enc", ".dec")
            with open(out_path, 'wb') as f_out:
                f_out.write(plaintext)

            return out_path
        except Exception:
            raise ValueError("Decryption failed: Integrity check error or wrong password")