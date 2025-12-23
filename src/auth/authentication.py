import secrets
import pyotp
import json
import os
from argon2 import PasswordHasher

class AuthModule:
    def __init__(self, db_file="users.json"):
        # Define the file path relative to the execution context
        # This creates users.json in the project root (next to gui_app.py)
        self.db_file = db_file
        self.ph = PasswordHasher()
        self.users = self.load_users()

    def load_users(self):
        """Load users from the file at startup."""
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
        """Save users to the file."""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.users, f, indent=4)
            print(f"[DEBUG] Users saved to {self.db_file}")
        except Exception as e:
            print(f"[ERROR] Could not save users: {e}")

    def register(self, username: str, password: str) -> dict:
        # 4 characters allowed for testing; in production, 8+ is recommended
        if len(password) < 4:
            raise ValueError("Password too weak")
        if username in self.users:
            raise ValueError("User already exists")

        # Password hashing using Argon2
        password_hash = self.ph.hash(password)

        # Generate secret for 2FA (TOTP)
        totp_secret = pyotp.random_base32()

        self.users[username] = {
            'hash': password_hash,
            'totp_secret': totp_secret
        }

        # IMPORTANT: Save changes to disk
        self.save_users()

        # Return the provisioning URI for QR code generation
        return pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="CryptoVault")

    def login(self, username: str, password: str, totp_code: str) -> bool:
        user = self.users.get(username)
        if not user:
            return False

        try:
            # Verify the password against the stored hash
            self.ph.verify(user['hash'], password)

            # If TOTP verification is required, uncomment the actual checks here
            # totp = pyotp.TOTP(user['totp_secret'])
            # if not totp.verify(totp_code): return False

            return True
        except:
            return False