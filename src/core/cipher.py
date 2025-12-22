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
                # Формула: E(x) = (x + k) mod 26
                processed = chr((ord(char) - ascii_offset + self.shift) % 26 + ascii_offset)
                result += processed
            else:
                result += char
        return result

    def decrypt(self, text: str) -> str:
        # Формула: D(x) = (x - k) mod 26
        original_shift = self.shift
        self.shift = -self.shift
        result = self.encrypt(text)
        self.shift = original_shift
        return result

class XORStreamCipher:
    """
    Symmetric Encryption.
    Потоковый шифр на основе XOR и генератора псевдослучайных чисел (LFSR-like).
    """
    def __init__(self, key: bytes):
        if len(key) < 1:
            raise ValueError("Key must not be empty")
        self.key = bytearray(key)

    def process(self, data: bytes) -> bytes:
        """Шифрует и дешифрует (операция симметрична)"""
        output = bytearray()
        key_len = len(self.key)

        for i, byte in enumerate(data):
            # XOR байта данных с байтом ключа
            # Для "сложности" добавляем простую ротацию ключа
            k = self.key[i % key_len]
            output.append(byte ^ k)

            # Динамическое обновление ключа (эмуляция stream state)
            self.key[i % key_len] = (k + 1) % 256

        return bytes(output)