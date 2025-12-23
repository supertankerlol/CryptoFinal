import os

class CaesarCipher:
    """
    Classical Cipher implementation.
    """
    def __init__(self, shift: int):
        self.shift = shift % 26

    def encrypt(self, text: str) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                # Formula: E(x) = (x + k) mod 26
                processed = chr((ord(char) - ascii_offset + self.shift) % 26 + ascii_offset)
                result += processed
            else:
                result += char
        return result

    def decrypt(self, text: str) -> str:
        # Formula: D(x) = (x - k) mod 26
        original_shift = self.shift
        self.shift = -self.shift
        result = self.encrypt(text)
        self.shift = original_shift
        return result

class XORStreamCipher:
    """
    Symmetric Encryption.
    Stream cipher based on XOR and a pseudo-random number generator (LFSR-like).
    """
    def __init__(self, key: bytes):
        if len(key) < 1:
            raise ValueError("Key must not be empty")
        self.key = bytearray(key)

    def process(self, data: bytes) -> bytes:
        """Encrypts and decrypts (operation is symmetric)"""
        output = bytearray()
        key_len = len(self.key)

        for i, byte in enumerate(data):
            # XOR data byte with key byte
            # Add simple key rotation for "complexity"
            k = self.key[i % key_len]
            output.append(byte ^ k)

            # Dynamic key update (emulating stream state)
            self.key[i % key_len] = (k + 1) % 256

        return bytes(output)