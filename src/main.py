import os
from src.auth.authentication import AuthModule
from src.messaging.messenger import MessagingModule
from src.files.file_enc import FileEncryptionModule
from src.ledger.blockchain import BlockchainModule
from src.core.cipher import CaesarCipher

def main():
    print("=== CryptoVault Security Suite v1.0 ===")

    # Инициализация модулей
    auth = AuthModule()
    files = FileEncryptionModule()
    ledger = BlockchainModule(difficulty=2)

    # 1. Регистрация (Auth Module)
    print("\n[!] Registering User 'Student'...")
    uri = auth.register("Student", "StrongP@ssw0rd2024")
    print(f"TOTP URI: {uri}")
    # Эмуляция логина (без ввода кода для демо)
    print("User logged in successfully.")

    ledger.log_event("LOGIN", "Student", "Success")

    # 2. Демонстрация Core Crypto (Caesar)
    print("\n[!] Testing Custom Crypto (Caesar Cipher)...")
    caesar = CaesarCipher(shift=3)
    msg = "SECRET"
    enc = caesar.encrypt(msg)
    print(f"Original: {msg} -> Encrypted: {enc} -> Decrypted: {caesar.decrypt(enc)}")

    # 3. Демонстрация шифрования файлов
    print("\n[!] Testing File Encryption...")
    # Создаем тестовый файл
    test_file = "secret_doc.txt"
    with open(test_file, "w") as f:
        f.write("This is top secret project data.")

    print(f"Encrypting {test_file}...")
    enc_path, f_hash = files.encrypt_file(test_file, "StrongP@ssw0rd2024")
    print(f"File encrypted to: {enc_path}")
    print(f"Original SHA-256: {f_hash}")

    # Логируем в блокчейн
    ledger.log_event("FILE_ENCRYPT", "Student", f"File: {test_file}, Hash: {f_hash}")

    print(f"Decrypting...")
    dec_path = files.decrypt_file(enc_path, "StrongP@ssw0rd2024")
    print(f"File decrypted to: {dec_path}")

    # 4. Проверка Блокчейна
    print("\n[!] Blockchain Audit Trail...")
    ledger.create_block()
    for block in ledger.chain:
        print(f"Block #{block['index']} [Hash: {block.get('hash', 'Genesis')[:10]}...]")
        for tx in block['transactions']:
            print(f"   - {tx['type']}: {tx['details']}")

if __name__ == "__main__":
    main()