import unittest
import os
from src.core.cipher import CaesarCipher, XORStreamCipher
from src.core.merkle import MerkleTree
from src.files.file_enc import FileEncryptionModule

class TestCoreCrypto(unittest.TestCase):
    def test_caesar(self):
        c = CaesarCipher(1)
        self.assertEqual(c.encrypt("ABC"), "BCD")
        self.assertEqual(c.decrypt("BCD"), "ABC")

    def test_xor_cipher(self):
        key = b'secret'
        cipher = XORStreamCipher(key)
        data = b'hello world'
        # XOR дважды возвращает исходное значение
        encrypted = cipher.process(data)
        # Нужно сбросить состояние ключа или создать новый экземпляр
        cipher2 = XORStreamCipher(key)
        decrypted = cipher2.process(encrypted)
        self.assertEqual(data, decrypted)

    def test_merkle_tree(self):
        txs = ["tx1", "tx2", "tx3"]
        tree = MerkleTree(txs)
        self.assertTrue(len(tree.root) > 0)

class TestModules(unittest.TestCase):
    def test_file_encryption(self):
        fem = FileEncryptionModule()
        fname = "test_unit.txt"
        password = "pass"

        with open(fname, "w") as f:
            f.write("data")

        enc, _ = fem.encrypt_file(fname, password)
        dec = fem.decrypt_file(enc, password)

        with open(dec, "r") as f:
            self.assertEqual(f.read(), "data")

        # Cleanup
        os.remove(fname)
        os.remove(enc)
        os.remove(dec)

if __name__ == '__main__':
    unittest.main()