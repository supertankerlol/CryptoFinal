import time
import hashlib
import json
import os
from src.core.merkle import MerkleTree

class BlockchainModule:
    def __init__(self, difficulty=2, db_file="ledger.json"):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = difficulty
        self.db_file = db_file

        if os.path.exists(self.db_file):
            self.load_chain()
        else:
            self.create_block(previous_hash="0") # Genesis block

    def load_chain(self):
        try:
            with open(self.db_file, 'r') as f:
                self.chain = json.load(f)
            print(f"[DEBUG] Ledger loaded from {self.db_file}")
        except:
            self.create_block(previous_hash="0")

    def save_chain(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def create_block(self, previous_hash=None):
        if not previous_hash:
            previous_hash = self.chain[-1]['hash'] if self.chain else "0"

        tx_strings = [str(tx) for tx in self.pending_transactions]
        if not tx_strings: tx_strings = ["EMPTY"]

        merkle_root = MerkleTree(tx_strings).root

        block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'transactions': self.pending_transactions,
            'merkle_root': merkle_root,
            'previous_hash': previous_hash,
            'nonce': 0
        }

        block = self.proof_of_work(block)
        self.chain.append(block)
        self.pending_transactions = []

        # ВАЖНО: Сохраняем на диск
        self.save_chain()
        return block

    def proof_of_work(self, block):
        target = "0" * self.difficulty
        while True:
            block_string = f"{block['index']}{block['timestamp']}{block['merkle_root']}{block['previous_hash']}{block['nonce']}"
            block_hash = hashlib.sha256(block_string.encode()).hexdigest()
            if block_hash.startswith(target):
                block['hash'] = block_hash
                return block
            block['nonce'] += 1

    def log_event(self, event_type, user, details):
        event = {
            'type': event_type,
            'user': user,
            'timestamp': time.time(),
            'details': details
        }
        self.pending_transactions.append(event)