import hashlib
from typing import List

class MerkleTree:
    """
    Merkle Tree implementation.
    Used in the Blockchain Module.
    """
    def __init__(self, transactions: List[str]):
        self.transactions = transactions
        self.root = self.build_tree(transactions)

    def build_tree(self, data: List[str]) -> str:
        # Hash initial data (leaves)
        hashes = [self._hash(d) for d in data]

        if not hashes:
            return ""

        # Build the tree from bottom up
        while len(hashes) > 1:
            # If the number of nodes is odd, duplicate the last element
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            next_level = []
            for i in range(0, len(hashes), 2):
                # Hash the pair (concatenation)
                combined = hashes[i] + hashes[i+1]
                next_level.append(self._hash(combined))
            hashes = next_level

        return hashes[0]

    def _hash(self, data: str) -> str:
        # Simplified wrapper around SHA-256 (allowed by Option B)
        return hashlib.sha256(data.encode()).hexdigest()