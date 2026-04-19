"""
BLOCKCHAIN MODULE
=================
Concepts Demonstrated:
  1. Block Structure (index, timestamp, data, previous_hash, nonce, hash)
  2. SHA-256 Hashing for block integrity
  3. Proof of Work (PoW) mining
  4. Merkle Tree for transaction integrity
  5. Chain Validation (immutability)
  6. Genesis Block creation
"""

import hashlib
import json
import time
import os
import difflib
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────
# MERKLE TREE
# ─────────────────────────────────────────────────────────────
class MerkleTree:
    """
    Merkle Tree: A binary tree where each leaf is a hash of data,
    and each internal node is a hash of its two children.
    Used in Bitcoin and Ethereum to efficiently verify data integrity.
    """

    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_tree(transactions)

    def hash_node(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def build_tree(self, transactions):
        if not transactions:
            return self.hash_node("EMPTY_BLOCK")

        # Leaf hashes
        hashes = [
            self.hash_node(json.dumps(tx, sort_keys=True))
            for tx in transactions
        ]

        # Build up the tree level by level
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # duplicate last node if odd
            hashes = [
                self.hash_node(hashes[i] + hashes[i + 1])
                for i in range(0, len(hashes), 2)
            ]

        return hashes[0]  # Merkle Root


# ─────────────────────────────────────────────────────────────
# BLOCK
# ─────────────────────────────────────────────────────────────
class Block:
    """
    A single Block in the chain.

    Fields:
      index         — position in the chain
      timestamp     — UTC time of creation
      transactions  — list of document records stored in this block
      previous_hash — hash of the previous block (links the chain)
      nonce         — number iterated during Proof of Work
      merkle_root   — Merkle root of all transactions
      hash          — SHA-256 hash of this block (found via PoW)
    """

    def __init__(self, index: int, transactions: list,
                 previous_hash: str, difficulty: int = 2):
        self.index = index
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce = 0
        self.merkle_root = MerkleTree(transactions).root
        # Mine the block (find valid hash)
        self.hash = self._mine()

    # ── Internal helpers ──────────────────────────────────────

    def _block_string(self) -> str:
        """Serialise block data (nonce excluded intentionally)."""
        return json.dumps({
            "index":         self.index,
            "timestamp":     self.timestamp,
            "transactions":  self.transactions,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "merkle_root":   self.merkle_root,
        }, sort_keys=True)

    def compute_hash(self) -> str:
        return hashlib.sha256(self._block_string().encode()).hexdigest()

    def _mine(self) -> str:
        """
        PROOF OF WORK:
        Keep incrementing nonce until hash starts with <difficulty> zeros.
        This makes block creation computationally expensive (tamper-proof).
        """
        target = "0" * self.difficulty
        while True:
            h = self.compute_hash()
            if h.startswith(target):
                return h
            self.nonce += 1

    # ── Serialisation ─────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "transactions":  self.transactions,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "difficulty":    self.difficulty,
            "merkle_root":   self.merkle_root,
            "hash":          self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        """Reconstruct a Block from a dictionary (for persistence)."""
        b = cls.__new__(cls)
        b.index         = data["index"]
        b.timestamp     = data["timestamp"]
        b.transactions  = data["transactions"]
        b.previous_hash = data["previous_hash"]
        b.difficulty    = data["difficulty"]
        b.nonce         = data["nonce"]
        b.merkle_root   = data["merkle_root"]
        b.hash          = data["hash"]
        return b


# ─────────────────────────────────────────────────────────────
# BLOCKCHAIN
# ─────────────────────────────────────────────────────────────
class Blockchain:
    """
    An append-only, tamper-evident chain of Blocks.

    Key properties:
      • Immutability  — changing any block invalidates all subsequent hashes
      • Transparency  — every record is publicly inspectable
      • Decentralised — (simulated; in production, nodes replicate the chain)
    """

    CHAIN_FILE = "blockchain_data.json"

    def __init__(self, difficulty: int = 2):
        self.difficulty = difficulty
        self.chain: list[Block] = []
        self._load_or_create()

    # ── Persistence ───────────────────────────────────────────

    def _load_or_create(self):
        if os.path.exists(self.CHAIN_FILE):
            try:
                with open(self.CHAIN_FILE, "r") as f:
                    data = json.load(f)
                self.chain = [Block.from_dict(b) for b in data]
                return
            except Exception:
                pass
        # Fresh chain → genesis block
        self.chain = [self._create_genesis_block()]
        self._save()

    def _save(self):
        with open(self.CHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    # ── Block operations ──────────────────────────────────────

    def _create_genesis_block(self) -> Block:
        return Block(
            index=0,
            transactions=[{"message": "Genesis Block — Secure Academic Document Verification System"}],
            previous_hash="0" * 64,
            difficulty=self.difficulty,
        )

    def last_block(self) -> Block:
        return self.chain[-1]

    def add_document(self, document_record: dict) -> Block:
        """
        Add a new document record as a new block.
        Each document gets its own block so it can be individually located.
        """
        new_block = Block(
            index=len(self.chain),
            transactions=[document_record],
            previous_hash=self.last_block().hash,
            difficulty=self.difficulty,
        )
        self.chain.append(new_block)
        self._save()
        return new_block

    # ── Verification ──────────────────────────────────────────

    def find_document(self, doc_hash: str):
        """
        Search every block for a matching document_hash.
        Returns (block_dict, transaction) or (None, None).
        """
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("document_hash") == doc_hash:
                    return block.to_dict(), tx
        return None, None

    def find_document_by_name(self, document_name: str):
        """
        Search every block for a document matching the uploaded filename.
        This enables deep analysis when the hash no longer matches.
        """
        target_name = (document_name or "").strip().lower()
        for block in reversed(self.chain):
            for tx in block.transactions:
                if (tx.get("document_name") or "").strip().lower() == target_name:
                    return block.to_dict(), tx
        return None, None

    def get_all_document_records(self):
        """Return all registered document transactions with block context."""
        records = []
        for block in reversed(self.chain):
            block_dict = block.to_dict()
            for tx in block.transactions:
                if tx.get("document_hash"):
                    records.append((block_dict, tx))
        return records

    def find_best_document_match(self, uploaded_name: str, normalized_names: list[str] | None = None):
        """
        Best-effort document match by filename similarity when exact filename isn't available.
        Returns (block_dict, transaction) or (None, None).
        """
        uploaded_name = (uploaded_name or "").strip().lower()
        if not uploaded_name:
            return None, None

        uploaded_stem, uploaded_suffix = os.path.splitext(uploaded_name)
        normalized_names = [n.strip().lower() for n in (normalized_names or []) if n]
        candidates = []

        for block_dict, tx in self.get_all_document_records():
            name = (tx.get("document_name") or "").strip().lower()
            if not name:
                continue
            stem, suffix = os.path.splitext(name)
            score = difflib.SequenceMatcher(None, uploaded_name, name).ratio()

            # Strong preference for same extension and similar basename
            if suffix == uploaded_suffix:
                score += 0.15
            if stem in normalized_names:
                score += 0.25
            if uploaded_stem in stem or stem in uploaded_stem:
                score += 0.2

            candidates.append((score, block_dict, tx))

        if not candidates:
            return None, None

        candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, best_block, best_tx = candidates[0]
        return (best_block, best_tx) if best_score >= 0.65 else (None, None)

    def is_chain_valid(self):
        """
        Validate the full chain:
          1. Each block's stored hash must equal its recomputed hash
          2. Each block's previous_hash must equal the previous block's hash
          3. Each block must satisfy the Proof of Work target
        """
        errors = []
        for i in range(1, len(self.chain)):
            cur  = self.chain[i]
            prev = self.chain[i - 1]

            recomputed = cur.compute_hash()
            if cur.hash != recomputed:
                errors.append(f"Block {i}: stored hash ≠ computed hash")

            if cur.previous_hash != prev.hash:
                errors.append(f"Block {i}: previous_hash mismatch")

            if not cur.hash.startswith("0" * self.difficulty):
                errors.append(f"Block {i}: Proof of Work invalid")

        if errors:
            return False, errors
        return True, ["All blocks valid ✔"]

    def get_stats(self) -> dict:
        total_docs = sum(
            1 for block in self.chain
            for tx in block.transactions
            if tx.get("document_hash")
        )
        return {
            "total_blocks":    len(self.chain),
            "total_documents": total_docs,
            "difficulty":      self.difficulty,
            "last_hash":       self.last_block().hash,
        }

    def to_dict(self) -> list:
        return [b.to_dict() for b in self.chain]
