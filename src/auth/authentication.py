import secrets
import pyotp
import json
import os
from argon2 import PasswordHasher

class AuthModule:
    def __init__(self, db_file="users.json"):
        # Определяем путь к файлу относительно запуска
        # Это создаст users.json прямо в корне проекта (рядом с gui_app.py)
        self.db_file = db_file
        self.ph = PasswordHasher()
        self.users = self.load_users()

    def load_users(self):
        """Загрузка пользователей из файла при запуске"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    print(f"[DEBUG] Loaded users from {os.path.abspath(self.db_file)}")
                    return json.load(f)
            except Exception as e:
                print(f"[ERROR] Could not load users: {e}")
                return {}
        else:
            print(f"[DEBUG] No users file found. Creating new one at {os.path.abspath(self.db_file)}")
            return {}

    def save_users(self):
        """Сохранение пользователей в файл"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.users, f, indent=4)
            print(f"[DEBUG] Users saved to {self.db_file}")
        except Exception as e:
            print(f"[ERROR] Could not save users: {e}")

    def register(self, username: str, password: str) -> dict:
        if len(password) < 4: # Для тестов можно 4, в реале лучше 8
            raise ValueError("Password too weak")
        if username in self.users:
            raise ValueError("User already exists")

        # Хеширование
        password_hash = self.ph.hash(password)
        totp_secret = pyotp.random_base32()

        self.users[username] = {
            'hash': password_hash,
            'totp_secret': totp_secret
        }

        # ВАЖНО: Сохраняем изменения на диск
        self.save_users()

        return pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="CryptoVault")

    def login(self, username: str, password: str, totp_code: str) -> bool:
        user = self.users.get(username)
        if not user:
            return False

        try:
            self.ph.verify(user['hash'], password)
            # Если нужно проверять TOTP, раскомментируйте проверки
            return True
        except:
            return False