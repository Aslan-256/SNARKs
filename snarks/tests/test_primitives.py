"""
Tests for cryptographic primitives.

Tests Merkle trees, PIR, and Fiat-Shamir transcripts.
"""

import unittest
from snarks.primitives import MerkleTree, SimulatedPIR, Transcript


class TestMerkleTree(unittest.TestCase):
    """Test Merkle tree construction and verification."""
    
    def test_binary_tree_creation(self):
        """Test basic binary Merkle tree."""
        data = [b"leaf0", b"leaf1", b"leaf2", b"leaf3"]
        tree = MerkleTree(data, arity=2)
        
        self.assertIsNotNone(tree.root)
        self.assertEqual(len(tree.leaves), 4)
    
    def test_authentication_path(self):
        """Test authentication path generation and verification."""
        data = [b"data0", b"data1", b"data2", b"data3"]
        tree = MerkleTree(data, arity=2)
        
        # Generate proof for leaf 2
        path = tree.get_authentication_path(2)
        
        # Verify the proof
        is_valid = tree.verify_authentication_path(2, b"data2", path)
        self.assertTrue(is_valid)
    
    def test_authentication_path_fails_wrong_data(self):
        """Test that wrong data fails verification."""
        data = [b"data0", b"data1", b"data2", b"data3"]
        tree = MerkleTree(data, arity=2)
        
        path = tree.get_authentication_path(2)
        
        # Try to verify with wrong data
        is_valid = tree.verify_authentication_path(2, b"wrong_data", path)
        self.assertFalse(is_valid)
    
    def test_squashed_tree_arity_4(self):
        """Test squashed Merkle tree with arity 4."""
        data = [f"item{i}".encode() for i in range(16)]
        tree = MerkleTree(data, arity=4)
        
        # Depth should be 2 (4^2 = 16)
        self.assertEqual(len(tree.tree), 3)  # levels: 16 -> 4 -> 1
        
        # Test authentication path
        path = tree.get_authentication_path(7)
        is_valid = tree.verify_authentication_path(7, b"item7", path)
        self.assertTrue(is_valid)
    
    def test_tree_with_odd_leaves(self):
        """Test tree construction with non-power-of-arity leaves."""
        data = [b"a", b"b", b"c", b"d", b"e"]
        tree = MerkleTree(data, arity=2)
        
        # Should handle padding gracefully
        path = tree.get_authentication_path(4)
        is_valid = tree.verify_authentication_path(4, b"e", path)
        self.assertTrue(is_valid)


class TestSimulatedPIR(unittest.TestCase):
    """Test simulated Private Information Retrieval."""
    
    def test_basic_pir_query(self):
        """Test basic PIR query and extraction."""
        pir = SimulatedPIR(security_parameter=128)
        database = [b"secret0", b"secret1", b"secret2", b"secret3"]
        
        # Query index 2
        index = 2
        query, secret_key = pir.query_gen(index, len(database))
        
        # Server responds
        response = pir.answer_gen(database, query)
        
        # Client extracts
        result = pir.extract(response, secret_key, index)
        
        self.assertEqual(result, b"secret2")
    
    def test_pir_multiple_queries(self):
        """Test multiple PIR queries on same database."""
        pir = SimulatedPIR()
        database = [f"item{i}".encode() for i in range(10)]
        
        for index in [0, 5, 9]:
            query, key = pir.query_gen(index, len(database))
            response = pir.answer_gen(database, query)
            result = pir.extract(response, key, index)
            
            self.assertEqual(result, f"item{index}".encode())
    
    def test_pir_invalid_index(self):
        """Test PIR with invalid index."""
        pir = SimulatedPIR()
        database = [b"a", b"b", b"c"]
        
        # Query out of bounds
        with self.assertRaises(ValueError):
            query, key = pir.query_gen(5, len(database))
            pir.answer_gen(database, query)
    
    def test_communication_complexity(self):
        """Test communication complexity calculation."""
        pir = SimulatedPIR()
        complexity = pir.get_communication_complexity(database_size=1000)
        
        self.assertIn('query_size', complexity)
        self.assertIn('response_overhead', complexity)
        self.assertIn('database_size', complexity)


class TestTranscript(unittest.TestCase):
    """Test Fiat-Shamir transcript."""
    
    def test_basic_absorption(self):
        """Test absorbing data into transcript."""
        transcript = Transcript(protocol_label="TestProtocol")
        
        transcript.absorb("message1", b"hello")
        transcript.absorb("message2", 12345)
        transcript.absorb("message3", "world")
        
        # Transcript should have recorded messages
        self.assertEqual(len(transcript.get_history()), 3)
    
    def test_challenge_generation(self):
        """Test generating challenges from transcript."""
        transcript = Transcript(protocol_label="Test")
        
        transcript.absorb("commitment", b"commitment_data")
        challenge = transcript.squeeze("challenge1", 32)
        
        # Should be 32 bytes
        self.assertEqual(len(challenge), 32)
        self.assertIsInstance(challenge, bytes)
    
    def test_deterministic_challenges(self):
        """Test that same transcript produces same challenges."""
        # Create two identical transcripts
        t1 = Transcript(protocol_label="Protocol1")
        t1.absorb("msg1", b"data1")
        t1.absorb("msg2", 42)
        c1 = t1.squeeze("chal", 32)
        
        t2 = Transcript(protocol_label="Protocol1")
        t2.absorb("msg1", b"data1")
        t2.absorb("msg2", 42)
        c2 = t2.squeeze("chal", 32)
        
        self.assertEqual(c1, c2)
    
    def test_different_order_different_challenge(self):
        """Test that message order affects challenges."""
        t1 = Transcript(protocol_label="Test")
        t1.absorb("a", b"first")
        t1.absorb("b", b"second")
        c1 = t1.squeeze("challenge", 16)
        
        t2 = Transcript(protocol_label="Test")
        t2.absorb("b", b"second")
        t2.absorb("a", b"first")
        c2 = t2.squeeze("challenge", 16)
        
        # Different order should give different challenge
        self.assertNotEqual(c1, c2)
    
    def test_field_element_generation(self):
        """Test generating field element challenges."""
        transcript = Transcript(protocol_label="FieldTest")
        
        p = 2**255 - 19  # Curve25519 field
        transcript.absorb("setup", b"params")
        
        challenge = transcript.squeeze_field_element("alpha", p)
        
        # Should be in valid range
        self.assertGreaterEqual(challenge, 0)
        self.assertLess(challenge, p)
    
    def test_multiple_field_elements(self):
        """Test generating multiple field elements."""
        transcript = Transcript(protocol_label="Multi")
        p = 101
        
        transcript.absorb("commitment", b"test")
        challenges = transcript.squeeze_field_elements("betas", p, 5)
        
        self.assertEqual(len(challenges), 5)
        for c in challenges:
            self.assertGreaterEqual(c, 0)
            self.assertLess(c, p)
    
    def test_transcript_fork(self):
        """Test forking transcripts for parallel proofs."""
        main = Transcript(protocol_label="Main")
        main.absorb("common", b"shared_data")
        
        # Fork for two sub-proofs
        branch1 = main.fork("proof1")
        branch2 = main.fork("proof2")
        
        branch1.absorb("specific1", b"data1")
        branch2.absorb("specific2", b"data2")
        
        c1 = branch1.squeeze("challenge", 16)
        c2 = branch2.squeeze("challenge", 16)
        
        # Branches should have different states
        self.assertNotEqual(c1, c2)


if __name__ == '__main__':
    unittest.main()
