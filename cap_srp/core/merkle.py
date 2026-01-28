"""
CAP-SRP Merkle Tree Implementation

This module provides a Merkle tree implementation for efficient verification
of event inclusion and integrity.

Merkle trees are used because:
1. O(log n) proof size - verify any single event without downloading all events
2. Tamper evidence - any modification changes the root hash
3. Append-only structure - matches the immutable event log model
4. Compatible with Certificate Transparency (RFC 6962)
5. Used by IETF SCITT for supply chain integrity

Key Concepts:
    - Leaf: Hash of an individual event
    - Internal Node: Hash of two child nodes concatenated
    - Root: The single hash at the top, representing all events
    - Inclusion Proof: Path from leaf to root proving event membership
    - Consistency Proof: Proves one tree is prefix of another

Usage:
    >>> from cap_srp.core.merkle import MerkleTree
    >>> 
    >>> # Create tree and add events
    >>> tree = MerkleTree()
    >>> tree.add_leaf(event.compute_hash())
    >>> 
    >>> # Get root for external anchoring
    >>> root = tree.root
    >>> 
    >>> # Generate inclusion proof for auditors
    >>> proof = tree.get_inclusion_proof(index)
    >>> 
    >>> # Verify proof
    >>> is_valid = tree.verify_inclusion_proof(leaf_hash, proof, root)
"""

import hashlib
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
import json
import base64


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class InclusionProof:
    """
    Proof that a leaf is included in the Merkle tree.
    
    Attributes:
        leaf_index: Index of the leaf in the tree
        leaf_hash: Hash of the leaf being proven
        proof_hashes: List of sibling hashes from leaf to root
        proof_directions: List of directions (0=left, 1=right) for each hash
        tree_size: Total number of leaves when proof was generated
        root_hash: The Merkle root at time of proof generation
    """
    leaf_index: int
    leaf_hash: str
    proof_hashes: List[str]
    proof_directions: List[int]  # 0 = hash goes on left, 1 = hash goes on right
    tree_size: int
    root_hash: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
            "proof_hashes": self.proof_hashes,
            "proof_directions": self.proof_directions,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'InclusionProof':
        """Create from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'InclusionProof':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ConsistencyProof:
    """
    Proof that one tree is a prefix of another (append-only property).
    
    This proves that the tree has only grown by appending leaves,
    not by modifying existing leaves.
    """
    first_tree_size: int
    second_tree_size: int
    proof_hashes: List[str]
    first_root: str
    second_root: str
    
    def to_dict(self) -> dict:
        return {
            "first_tree_size": self.first_tree_size,
            "second_tree_size": self.second_tree_size,
            "proof_hashes": self.proof_hashes,
            "first_root": self.first_root,
            "second_root": self.second_root
        }


class MerkleTree:
    """
    Append-only Merkle tree for event log integrity.
    
    This implementation follows RFC 6962 (Certificate Transparency) conventions
    for hash computation and proof generation.
    
    Hash computation:
        - Leaf hash: SHA256(0x00 || leaf_data)
        - Internal hash: SHA256(0x01 || left_hash || right_hash)
    
    The 0x00/0x01 prefix prevents second-preimage attacks where an attacker
    might try to present an internal node as a leaf or vice versa.
    """
    
    LEAF_PREFIX = b'\x00'
    NODE_PREFIX = b'\x01'
    
    def __init__(self):
        """Initialize an empty Merkle tree."""
        self._leaves: List[bytes] = []
        self._nodes: List[List[bytes]] = [[]]  # nodes[0] = leaves, nodes[1] = level 1, etc.
        self._root: Optional[bytes] = None
    
    @property
    def size(self) -> int:
        """Get the number of leaves in the tree."""
        return len(self._leaves)
    
    @property
    def root(self) -> Optional[str]:
        """Get the current Merkle root as hex string."""
        if self._root is None:
            return None
        return self._root.hex()
    
    @property
    def root_bytes(self) -> Optional[bytes]:
        """Get the current Merkle root as bytes."""
        return self._root
    
    def _hash_leaf(self, data: bytes) -> bytes:
        """Hash a leaf with the leaf prefix."""
        return sha256(self.LEAF_PREFIX + data)
    
    def _hash_nodes(self, left: bytes, right: bytes) -> bytes:
        """Hash two nodes together with the node prefix."""
        return sha256(self.NODE_PREFIX + left + right)
    
    def add_leaf(self, leaf_hash: str) -> int:
        """
        Add a leaf to the tree.
        
        Args:
            leaf_hash: The hash of the event (hex string)
            
        Returns:
            int: Index of the added leaf
        """
        # Convert hex string to bytes and hash with leaf prefix
        leaf_data = bytes.fromhex(leaf_hash.replace('sha256:', ''))
        leaf = self._hash_leaf(leaf_data)
        
        self._leaves.append(leaf)
        self._rebuild_tree()
        
        return len(self._leaves) - 1
    
    def add_leaf_bytes(self, leaf_data: bytes) -> int:
        """
        Add a leaf to the tree from raw bytes.
        
        Args:
            leaf_data: The raw data to hash as a leaf
            
        Returns:
            int: Index of the added leaf
        """
        leaf = self._hash_leaf(leaf_data)
        self._leaves.append(leaf)
        self._rebuild_tree()
        return len(self._leaves) - 1
    
    def _rebuild_tree(self):
        """Rebuild the tree from leaves up to root."""
        if not self._leaves:
            self._root = None
            self._nodes = [[]]
            return
        
        # Start with leaves
        self._nodes = [self._leaves.copy()]
        
        # Build each level
        current_level = self._leaves.copy()
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Two nodes to combine
                    next_level.append(self._hash_nodes(current_level[i], current_level[i + 1]))
                else:
                    # Odd node - promote to next level
                    next_level.append(current_level[i])
            self._nodes.append(next_level)
            current_level = next_level
        
        self._root = current_level[0] if current_level else None
    
    def get_inclusion_proof(self, index: int) -> InclusionProof:
        """
        Generate an inclusion proof for the leaf at the given index.
        
        Args:
            index: Index of the leaf to prove
            
        Returns:
            InclusionProof: Proof that can verify leaf membership
            
        Raises:
            IndexError: If index is out of range
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self._leaves) - 1}]")
        
        proof_hashes = []
        proof_directions = []
        
        current_index = index
        for level in range(len(self._nodes) - 1):
            level_nodes = self._nodes[level]
            
            # Determine sibling index
            if current_index % 2 == 0:
                # Current is left child, sibling is right
                sibling_index = current_index + 1
                if sibling_index < len(level_nodes):
                    proof_hashes.append(level_nodes[sibling_index].hex())
                    proof_directions.append(1)  # Sibling goes on right
            else:
                # Current is right child, sibling is left
                sibling_index = current_index - 1
                proof_hashes.append(level_nodes[sibling_index].hex())
                proof_directions.append(0)  # Sibling goes on left
            
            # Move to parent index
            current_index = current_index // 2
        
        return InclusionProof(
            leaf_index=index,
            leaf_hash=self._leaves[index].hex(),
            proof_hashes=proof_hashes,
            proof_directions=proof_directions,
            tree_size=len(self._leaves),
            root_hash=self.root or ""
        )
    
    @staticmethod
    def verify_inclusion_proof(
        leaf_hash: str,
        proof: InclusionProof,
        expected_root: str
    ) -> bool:
        """
        Verify an inclusion proof.
        
        Args:
            leaf_hash: Hash of the leaf to verify (hex string)
            proof: The inclusion proof
            expected_root: Expected Merkle root (hex string)
            
        Returns:
            bool: True if the proof is valid
        """
        # Start with the leaf hash from the proof
        current_hash = bytes.fromhex(proof.leaf_hash)
        
        # Apply each proof step
        for sibling_hash, direction in zip(proof.proof_hashes, proof.proof_directions):
            sibling = bytes.fromhex(sibling_hash)
            if direction == 0:
                # Sibling is on the left
                current_hash = sha256(MerkleTree.NODE_PREFIX + sibling + current_hash)
            else:
                # Sibling is on the right
                current_hash = sha256(MerkleTree.NODE_PREFIX + current_hash + sibling)
        
        return current_hash.hex() == expected_root
    
    def get_leaf_hash(self, index: int) -> str:
        """Get the hash of a leaf at the given index."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range")
        return self._leaves[index].hex()
    
    def to_dict(self) -> dict:
        """Export tree state for serialization."""
        return {
            "size": self.size,
            "root": self.root,
            "leaves": [leaf.hex() for leaf in self._leaves]
        }
    
    def to_json(self) -> str:
        """Export tree state as JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_leaves(cls, leaf_hashes: List[str]) -> 'MerkleTree':
        """
        Create a tree from a list of leaf hashes.
        
        Args:
            leaf_hashes: List of event hashes (hex strings)
            
        Returns:
            MerkleTree: Populated tree
        """
        tree = cls()
        for leaf_hash in leaf_hashes:
            tree.add_leaf(leaf_hash)
        return tree


class AnchoredMerkleRoot:
    """
    A Merkle root that has been anchored to an external timestamp authority.
    
    This provides proof that the root existed at a specific point in time,
    enabling long-term verification even if the original signer's key
    is later compromised.
    """
    
    def __init__(
        self,
        root_hash: str,
        tree_size: int,
        anchor_timestamp: str,
        anchor_type: str,
        anchor_proof: str
    ):
        """
        Initialize an anchored root.
        
        Args:
            root_hash: The Merkle root hash
            tree_size: Number of leaves in the tree at anchoring
            anchor_timestamp: ISO 8601 timestamp from the anchor
            anchor_type: Type of anchor (e.g., "RFC3161", "BLOCKCHAIN", "WITNESS")
            anchor_proof: The proof from the anchor (base64 or hex encoded)
        """
        self.root_hash = root_hash
        self.tree_size = tree_size
        self.anchor_timestamp = anchor_timestamp
        self.anchor_type = anchor_type
        self.anchor_proof = anchor_proof
    
    def to_dict(self) -> dict:
        return {
            "root_hash": self.root_hash,
            "tree_size": self.tree_size,
            "anchor_timestamp": self.anchor_timestamp,
            "anchor_type": self.anchor_type,
            "anchor_proof": self.anchor_proof
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AnchoredMerkleRoot':
        return cls(**data)
