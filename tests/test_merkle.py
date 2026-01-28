"""
Tests for CAP-SRP Merkle Tree Module

Tests cover:
- Tree construction
- Inclusion proof generation
- Proof verification
- Edge cases
"""

import pytest
from cap_srp.core.merkle import MerkleTree, InclusionProof
from cap_srp.core.events import hash_data


class TestMerkleTree:
    """Test Merkle tree operations."""
    
    def test_empty_tree(self):
        """Empty tree should have no root."""
        tree = MerkleTree()
        assert tree.root is None
        assert tree.size == 0
    
    def test_single_leaf(self):
        """Single leaf tree should have valid root."""
        tree = MerkleTree()
        tree.add_leaf(hash_data("test").replace("sha256:", ""))
        
        assert tree.root is not None
        assert tree.size == 1
    
    def test_multiple_leaves(self):
        """Multiple leaves should produce valid root."""
        tree = MerkleTree()
        
        for i in range(10):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        assert tree.root is not None
        assert tree.size == 10
    
    def test_root_changes_with_new_leaf(self):
        """Adding leaf should change root."""
        tree = MerkleTree()
        tree.add_leaf(hash_data("first").replace("sha256:", ""))
        root1 = tree.root
        
        tree.add_leaf(hash_data("second").replace("sha256:", ""))
        root2 = tree.root
        
        assert root1 != root2
    
    def test_deterministic_construction(self):
        """Same leaves should produce same root."""
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        
        for i in range(5):
            leaf_hash = hash_data(f"leaf{i}").replace("sha256:", "")
            tree1.add_leaf(leaf_hash)
            tree2.add_leaf(leaf_hash)
        
        assert tree1.root == tree2.root


class TestInclusionProof:
    """Test Merkle inclusion proofs."""
    
    def test_proof_for_single_leaf(self):
        """Single leaf tree should have empty proof path."""
        tree = MerkleTree()
        tree.add_leaf(hash_data("test").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(0)
        
        assert proof.leaf_index == 0
        assert proof.tree_size == 1
        assert proof.root_hash == tree.root
    
    def test_proof_for_first_leaf(self):
        """Should generate valid proof for first leaf."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(0)
        
        assert proof.leaf_index == 0
        assert proof.tree_size == 8
        assert len(proof.proof_hashes) > 0
    
    def test_proof_for_last_leaf(self):
        """Should generate valid proof for last leaf."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(7)
        
        assert proof.leaf_index == 7
        assert proof.tree_size == 8
    
    def test_invalid_index_raises_error(self):
        """Invalid leaf index should raise error."""
        tree = MerkleTree()
        tree.add_leaf(hash_data("test").replace("sha256:", ""))
        
        with pytest.raises(IndexError):
            tree.get_inclusion_proof(1)
        
        with pytest.raises(IndexError):
            tree.get_inclusion_proof(-1)
    
    def test_proof_verification(self):
        """Generated proof should verify correctly."""
        tree = MerkleTree()
        for i in range(16):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        # Test proof for each leaf
        for i in range(16):
            proof = tree.get_inclusion_proof(i)
            is_valid = MerkleTree.verify_inclusion_proof(
                proof.leaf_hash,
                proof,
                tree.root
            )
            assert is_valid, f"Proof verification failed for leaf {i}"
    
    def test_proof_fails_with_wrong_root(self):
        """Proof should fail with wrong root."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(0)
        
        is_valid = MerkleTree.verify_inclusion_proof(
            proof.leaf_hash,
            proof,
            "wrong_root_hash"
        )
        assert not is_valid
    
    def test_proof_fails_with_tampered_leaf(self):
        """Proof should fail if leaf hash is tampered."""
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(0)
        
        is_valid = MerkleTree.verify_inclusion_proof(
            "tampered_leaf_hash",
            proof,
            tree.root
        )
        assert not is_valid


class TestProofSerialization:
    """Test proof serialization."""
    
    def test_proof_to_dict(self):
        """Proof should serialize to dict."""
        tree = MerkleTree()
        for i in range(4):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        proof = tree.get_inclusion_proof(0)
        d = proof.to_dict()
        
        assert 'leaf_index' in d
        assert 'leaf_hash' in d
        assert 'proof_hashes' in d
        assert 'root_hash' in d
    
    def test_proof_roundtrip(self):
        """Proof should survive serialization roundtrip."""
        tree = MerkleTree()
        for i in range(4):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        original_proof = tree.get_inclusion_proof(0)
        json_str = original_proof.to_json()
        restored_proof = InclusionProof.from_json(json_str)
        
        assert restored_proof.leaf_index == original_proof.leaf_index
        assert restored_proof.leaf_hash == original_proof.leaf_hash
        assert restored_proof.root_hash == original_proof.root_hash
        assert restored_proof.proof_hashes == original_proof.proof_hashes


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_power_of_two_leaves(self):
        """Power of two leaves should work correctly."""
        for power in [1, 2, 4, 8, 16]:
            tree = MerkleTree()
            for i in range(power):
                tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
            
            assert tree.size == power
            
            # All proofs should verify
            for i in range(power):
                proof = tree.get_inclusion_proof(i)
                assert MerkleTree.verify_inclusion_proof(
                    proof.leaf_hash,
                    proof,
                    tree.root
                )
    
    def test_non_power_of_two_leaves(self):
        """Non power of two leaves should work correctly."""
        for count in [3, 5, 7, 9, 15]:
            tree = MerkleTree()
            for i in range(count):
                tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
            
            assert tree.size == count
            
            # All proofs should verify
            for i in range(count):
                proof = tree.get_inclusion_proof(i)
                assert MerkleTree.verify_inclusion_proof(
                    proof.leaf_hash,
                    proof,
                    tree.root
                )
    
    def test_large_tree(self):
        """Large tree should work correctly."""
        tree = MerkleTree()
        for i in range(1000):
            tree.add_leaf(hash_data(f"leaf{i}").replace("sha256:", ""))
        
        assert tree.size == 1000
        
        # Spot check some proofs
        for i in [0, 100, 500, 999]:
            proof = tree.get_inclusion_proof(i)
            assert MerkleTree.verify_inclusion_proof(
                proof.leaf_hash,
                proof,
                tree.root
            )
    
    def test_from_leaves_classmethod(self):
        """from_leaves should construct valid tree."""
        leaves = [hash_data(f"leaf{i}").replace("sha256:", "") for i in range(10)]
        tree = MerkleTree.from_leaves(leaves)
        
        assert tree.size == 10
        assert tree.root is not None
