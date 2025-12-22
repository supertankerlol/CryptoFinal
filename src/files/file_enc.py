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
        """Генерация мастер-ключа из пароля (PBKDF2)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    def encrypt_file(self, file_path: str, password: str) -> str:
        """
        Шифрует файл.
        Возвращает путь к зашифрованному файлу.
        Формат файла: [Salt(16)] [Nonce(12)] [Encrypted_FEK] [Ciphertext...]
        """
        # 1. Подготовка ключей
        salt = os.urandom(16)
        master_key = self._derive_master_key(password, salt)

        # [cite_start]File Encryption Key (FEK) - случайный ключ для самого файла [cite: 569]
        fek = AESGCM.generate_key(bit_length=256)

        # Шифруем FEK с помощью мастер-ключа
        aesgcm_master = AESGCM(master_key)
        fek_nonce = os.urandom(12)
        encrypted_fek = aesgcm_master.encrypt(fek_nonce, fek, None)

        # 2. Подготовка шифрования контента
        aesgcm_file = AESGCM(fek)
        file_nonce = os.urandom(12)

        output_path = file_path + ".enc"

        # [cite_start] Хеш оригинала для проверки целостности [cite: 573]
        file_hash = hashlib.sha256()

        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Записываем заголовок
            f_out.write(salt)              # 16 bytes
            f_out.write(fek_nonce)         # 12 bytes
            f_out.write(encrypted_fek)     # len(fek) + 16 tag
            f_out.write(file_nonce)        # 12 bytes

            # Потоковое шифрование не поддерживается напрямую в AES-GCM (one-shot),
            # но для учебного проекта допустимо загрузить файл целиком или шифровать чанками (с ограничениями).
            # Для GCM безопаснее шифровать весь блок. Если файл огромный - используют AES-CTR + HMAC.
            # Здесь загрузим контент для GCM (как в примере лекций).
            data = f_in.read()
            file_hash.update(data)

            ciphertext = aesgcm_file.encrypt(file_nonce, data, None)
            f_out.write(ciphertext)

        return output_path, file_hash.hexdigest()

    def decrypt_file(self, enc_file_path: str, password: str) -> str:
        with open(enc_file_path, 'rb') as f:
            # Читаем метаданные
            salt = f.read(16)
            fek_nonce = f.read(12)
            # Длина ключа 32 байта + 16 байт tag = 48 байт
            encrypted_fek = f.read(48)
            file_nonce = f.read(12)
            ciphertext = f.read()

        # 1. Восстанавливаем мастер-ключ
        master_key = self._derive_master_key(password, salt)

        try:
            # 2. Расшифровываем FEK
            aesgcm_master = AESGCM(master_key)
            fek = aesgcm_master.decrypt(fek_nonce, encrypted_fek, None)

            # 3. Расшифровываем контент
            aesgcm_file = AESGCM(fek)
            plaintext = aesgcm_file.decrypt(file_nonce, ciphertext, None)

            # Сохраняем расшифрованный файл
            out_path = enc_file_path.replace(".enc", ".dec")
            with open(out_path, 'wb') as f_out:
                f_out.write(plaintext)

            return out_path
        except Exception:
            raise ValueError("Decryption failed: Integrity check error or wrong password")