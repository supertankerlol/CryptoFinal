import hashlib
from typing import List

class MerkleTree:
    """
    Реализация Merkle Tree[cite: 181].
    Используется в Blockchain Module[cite: 118].
    """
    def __init__(self, transactions: List[str]):
        self.transactions = transactions
        self.root = self.build_tree(transactions)

    def build_tree(self, data: List[str]) -> str:
        # Хешируем начальные данные (листья)
        hashes = [self._hash(d) for d in data]

        if not hashes:
            return ""

        # Строим дерево снизу вверх
        while len(hashes) > 1:
            # Если количество нечетное, дублируем последний элемент [cite: 121]
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            next_level = []
            for i in range(0, len(hashes), 2):
                # Хешируем пару (concatenation)
                combined = hashes[i] + hashes[i+1]
                next_level.append(self._hash(combined))
            hashes = next_level

        return hashes[0]

    def _hash(self, data: str) -> str:
        # Упрощенная обертка над SHA-256 (допустимо по Option B) [cite: 181]
        return hashlib.sha256(data.encode()).hexdigest()