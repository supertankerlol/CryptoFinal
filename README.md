Guide how to start App

pip install -r requirements.txt

python gui_app.py

Project Overview:

1. Authentication Module
Location: src/auth/authentication.py

Functionality
Handles user registration and login securely. The system adheres to the "Zero Knowledge" principle regarding passwords—plain text passwords are never stored.

Technical Implementation
Argon2id: Instead of fast hashing algorithms (like SHA-256), we use Argon2id. It is a memory-hard function, making it resistant to GPU-based brute-force attacks and rainbow table attacks.

Salting: A unique random salt is automatically generated and combined with the password before hashing.

MFA (Multi-Factor Authentication): The system generates a TOTP (Time-based One-Time Password) secret for integration with apps like Google Authenticator.

Key Code Snippet:
Python

# src/auth/authentication.py
def register(self, username, password):
    # Hashes password using Argon2id (Salt is handled internally)
    password_hash = self.ph.hash(password)
    totp_secret = pyotp.random_base32()
    
    # Store ONLY the hash, never the password
    self.users[username] = {'hash': password_hash, ...}


2. File Encryption Module
Location: src/files/file_enc.py

Functionality
Ensures the confidentiality and integrity of local files. It encrypts files so they can only be read with the correct password.

Technical Implementation (Hybrid Encryption)
We use a Key Wrapping scheme to allow efficient password changes without re-encrypting the entire file payload.

FEK (File Encryption Key): A random 256-bit key is generated for the file.

Data Encryption: The file content is encrypted with the FEK using AES-256-GCM.

Key Encryption: The FEK itself is encrypted using a Master Key derived from the user's password (via PBKDF2).

Integrity: The GCM mode provides an authentication tag. If the encrypted file is corrupted or tampered with, decryption will fail immediately.

Key Code Snippet:
Python

# src/files/file_enc.py
def encrypt_file(self, file_path, password):
    # 1. Generate random File Encryption Key (FEK)
    fek = AESGCM.generate_key(bit_length=256)
    
    # 2. Encrypt FEK with Master Key (derived from password)
    master_key = self._derive_master_key(password, salt)
    encrypted_fek = aesgcm_master.encrypt(fek_nonce, fek, None)
    
    # 3. Encrypt actual file content using FEK
    ciphertext = aesgcm_file.encrypt(file_nonce, data, None)

3. Blockchain Ledger (Audit Trail)
Location: src/ledger/blockchain.py & src/core/merkle.py

Functionality
Acts as a "Digital Notary." It records all critical system events (logins, file operations) into an immutable ledger.

Technical Implementation
Linked Chain: Each block contains the SHA-256 hash of the previous block. Changing an old block invalidates the entire subsequent chain.

Merkle Tree: All transactions within a block are hashed into a single Merkle Root. This ensures efficient integrity verification of the block's data.

Proof of Work (Mining): To add a block, the system must solve a computational puzzle (finding a nonce that results in a hash starting with specific zeros, e.g., 00...). This prevents spam and history rewriting.

Key Code Snippet:
Python

# src/ledger/blockchain.py
def create_block(self):
    # Construct Merkle Root from pending transactions
    merkle_root = MerkleTree(self.pending_transactions).root
    
    # Proof of Work: Find nonce such that hash starts with "00"
    block = self.proof_of_work(block_data)
    self.chain.append(block)


4. Secure Messaging Module
Location: src/messaging/messenger.py

Functionality
Simulates secure End-to-End Encrypted (E2EE) communication between two parties (Alice and Bob).

Technical Implementation
ECDH (Elliptic Curve Diffie-Hellman): Used for Key Exchange. Both parties combine their private key with the other's public key to derive a shared secret without transmitting it.

HKDF: The shared secret is processed into a strong symmetric key.

AES-GCM: The message is encrypted with this derived key.

Key Code Snippet:
Python

# src/messaging/messenger.py
def encrypt_message(self, recipient_pub, message):
    # Derive Shared Secret (ECDH)
    shared_key = self.private_key.exchange(ec.ECDH(), recipient_pub)
    
    # Encrypt message using derived key
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    

5. Data Persistence
The application maintains state across sessions using local JSON storage (located in the project root):

users.json: Stores usernames, Argon2 password hashes, and TOTP secrets.

ledger.json: Stores the entire Blockchain history (blocks, transactions, previous hashes).

