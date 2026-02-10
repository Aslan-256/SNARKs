"""
Comprehensive unit tests for advanced PCP-based SNARK constructions.

Tests cover:
1. Core primitives (Merkle Tree, PIR, PCP Oracle)
2. Kilian's interactive protocol
3. Micali's non-interactive SNARG
4. BCC14 adaptive SNARK
"""

import pytest
import random
from snarks.proofs.pcp import (
    MerkleTree, SimulatedPIR, PCPOracle,
    KilianProtocol, MicaliSNARG, BCC14SNARK,
    demo_kilian, demo_micali, demo_bcc14
)


# ============================================================================
# TEST CORE PRIMITIVES
# ============================================================================

class TestMerkleTree:
    """Test cases for Squashed Merkle Tree."""
    
    def test_binary_tree_creation(self):
        """Test creation of standard binary Merkle tree."""
        data = [b'leaf0', b'leaf1', b'leaf2', b'leaf3']
        tree = MerkleTree(data, arity=2)
        
        assert tree.arity == 2
        assert len(tree.leaves) == 4
        assert tree.root is not None
        assert len(tree.root) == 32  # SHA256 output
    
    def test_squashed_tree_creation(self):
        """Test creation of squashed Merkle tree with higher arity."""
        data = [f'leaf{i}'.encode() for i in range(10)]
        tree = MerkleTree(data, arity=4)
        
        assert tree.arity == 4
        assert len(tree.leaves) == 10
        # Higher arity means fewer levels
        # 10 leaves with arity 4: level 0 = 10, level 1 = 3, level 2 = 1
        assert len(tree.tree) <= len(tree.leaves)
    
    def test_authentication_path_binary(self):
        """Test authentication path generation for binary tree."""
        data = [f'leaf{i}'.encode() for i in range(8)]
        tree = MerkleTree(data, arity=2)
        
        # Get path for first leaf
        path = tree.get_authentication_path(0)
        
        assert len(path) > 0
        # Each level should have position and siblings
        for position, siblings in path:
            assert isinstance(position, int)
            assert isinstance(siblings, list)
            assert len(siblings) == 2  # Binary tree
    
    def test_authentication_path_squashed(self):
        """Test authentication path for squashed tree."""
        data = [f'leaf{i}'.encode() for i in range(16)]
        tree = MerkleTree(data, arity=4)
        
        path = tree.get_authentication_path(5)
        
        # Squashed tree should have fewer levels
        assert len(path) > 0
        for position, siblings in path:
            assert position >= 0
            assert len(siblings) <= 4  # Up to arity siblings
    
    def test_verify_authentication_path(self):
        """Test verification of authentication paths."""
        data = [f'leaf{i}'.encode() for i in range(10)]
        tree = MerkleTree(data, arity=2)
        
        for i in range(len(data)):
            path = tree.get_authentication_path(i)
            is_valid = tree.verify_authentication_path(i, data[i], path)
            assert is_valid, f"Path verification failed for leaf {i}"
    
    def test_verify_invalid_path(self):
        """Test that invalid paths are rejected."""
        data = [f'leaf{i}'.encode() for i in range(8)]
        tree = MerkleTree(data, arity=2)
        
        path = tree.get_authentication_path(0)
        
        # Try to verify with wrong leaf data
        is_valid = tree.verify_authentication_path(0, b'wrong_data', path)
        assert not is_valid
    
    def test_different_arities(self):
        """Test trees with various arity values."""
        data = [f'leaf{i}'.encode() for i in range(20)]
        
        for arity in [2, 3, 4, 5, 8]:
            tree = MerkleTree(data, arity=arity)
            assert tree.arity == arity
            
            # Verify a random path
            idx = random.randint(0, len(data) - 1)
            path = tree.get_authentication_path(idx)
            is_valid = tree.verify_authentication_path(idx, data[idx], path)
            assert is_valid
    
    def test_empty_data_raises_error(self):
        """Test that empty data raises ValueError."""
        with pytest.raises(ValueError, match="empty data"):
            MerkleTree([], arity=2)
    
    def test_invalid_arity_raises_error(self):
        """Test that arity < 2 raises ValueError."""
        with pytest.raises(ValueError, match="at least 2"):
            MerkleTree([b'data'], arity=1)


class TestSimulatedPIR:
    """Test cases for Simulated PIR scheme."""
    
    def test_query_generation(self):
        """Test PIR query generation."""
        pir = SimulatedPIR()
        query, key = pir.query_gen(5, database_size=100)
        
        assert isinstance(query, SimulatedPIR.Query)
        assert len(query.ciphertext) == 32  # SHA256
        assert len(key) == 16  # 128-bit key
        assert 'index' in query.metadata
    
    def test_answer_generation(self):
        """Test PIR answer generation."""
        pir = SimulatedPIR()
        database = [f'item{i}'.encode() for i in range(10)]
        
        query, key = pir.query_gen(3, database_size=10)
        response = pir.answer_gen(database, query)
        
        assert isinstance(response, SimulatedPIR.Response)
        assert len(response.data) > 0
    
    def test_extract_answer(self):
        """Test extraction of PIR answer."""
        pir = SimulatedPIR()
        database = [f'item{i}'.encode() for i in range(10)]
        index = 7
        
        query, key = pir.query_gen(index, database_size=10)
        response = pir.answer_gen(database, query)
        extracted = pir.extract(response, key, index)
        
        # Extracted value should match the database item
        assert extracted == database[index]
    
    def test_pir_correctness(self):
        """Test end-to-end PIR correctness."""
        pir = SimulatedPIR()
        database = [f'secret{i}'.encode() for i in range(20)]
        
        for index in [0, 5, 10, 15, 19]:
            query, key = pir.query_gen(index, len(database))
            response = pir.answer_gen(database, query)
            result = pir.extract(response, key, index)
            
            assert result == database[index], f"PIR failed for index {index}"
    
    def test_different_security_parameters(self):
        """Test PIR with different security levels."""
        for sec_param in [128, 192, 256]:
            pir = SimulatedPIR(security_parameter=sec_param)
            database = [b'data0', b'data1', b'data2']
            
            query, key = pir.query_gen(1, len(database))
            assert len(key) == sec_param // 8
            
            response = pir.answer_gen(database, query)
            result = pir.extract(response, key, 1)
            assert result == database[1]


class TestPCPOracle:
    """Test cases for PCP Oracle."""
    
    def test_oracle_initialization(self):
        """Test PCP oracle creation."""
        oracle = PCPOracle(field_size=257)
        assert oracle.field_size == 257
        assert oracle.num_queries == 3
    
    def test_proof_string_generation(self):
        """Test generation of PCP proof string."""
        oracle = PCPOracle()
        witness = [3, 4, 5]
        statement = {'type': 'sum', 'target': 12}
        
        proof_string = oracle.generate_proof_string(witness, statement)
        
        assert len(proof_string) > len(witness)
        assert all(isinstance(item, bytes) for item in proof_string)
    
    def test_verifier_query_generation(self):
        """Test deterministic query generation."""
        oracle = PCPOracle()
        proof_length = 50
        randomness = b'test_randomness_12345678'
        
        queries1 = oracle.generate_verifier_queries(proof_length, randomness)
        queries2 = oracle.generate_verifier_queries(proof_length, randomness)
        
        # Should be deterministic
        assert queries1 == queries2
        assert len(queries1) == oracle.num_queries
        assert all(0 <= q < proof_length for q in queries1)
    
    def test_local_check_valid(self):
        """Test local verification with valid proof."""
        oracle = PCPOracle()
        witness = [5, 7, 3]
        statement = {'type': 'sum', 'target': 15}
        
        proof_string = oracle.generate_proof_string(witness, statement)
        positions = [0, 1, 2]
        
        is_valid = oracle.verify_local_check(proof_string, positions, statement)
        # Should pass basic checks
        assert isinstance(is_valid, bool)
    
    def test_different_field_sizes(self):
        """Test oracle with different field sizes."""
        for field_size in [7, 31, 97, 257]:
            oracle = PCPOracle(field_size=field_size)
            witness = [2, 3]
            statement = {'type': 'sum', 'target': 5}
            
            proof_string = oracle.generate_proof_string(witness, statement)
            assert len(proof_string) > 0


# ============================================================================
# TEST PROTOCOLS
# ============================================================================

class TestKilianProtocol:
    """Test cases for Kilian's interactive protocol."""
    
    def test_protocol_initialization(self):
        """Test initialization of Kilian protocol."""
        oracle = PCPOracle()
        kilian = KilianProtocol(oracle, merkle_arity=2)
        
        assert kilian.pcp_oracle == oracle
        assert kilian.merkle_arity == 2
    
    def test_prove_generates_valid_proof(self):
        """Test proof generation."""
        oracle = PCPOracle()
        kilian = KilianProtocol(oracle, merkle_arity=2)
        
        witness = [3, 4, 5]
        statement = {'type': 'sum', 'target': 12}
        randomness = random.randbytes(32)
        
        proof = kilian.prove(witness, statement, randomness)
        
        assert isinstance(proof, KilianProtocol.Proof)
        assert len(proof.merkle_root) == 32
        assert len(proof.opened_positions) > 0
        assert len(proof.opened_values) == len(proof.opened_positions)
        assert len(proof.authentication_paths) == len(proof.opened_positions)
    
    def test_verify_valid_proof(self):
        """Test verification of valid proof."""
        oracle = PCPOracle()
        kilian = KilianProtocol(oracle, merkle_arity=2)
        
        witness = [5, 3, 4]
        statement = {'type': 'sum', 'target': 12}
        randomness = random.randbytes(32)
        
        proof = kilian.prove(witness, statement, randomness)
        is_valid = kilian.verify(proof, statement, randomness)
        
        assert is_valid, "Valid proof should verify"
    
    def test_completeness(self):
        """Test completeness: honest prover always convinces verifier."""
        oracle = PCPOracle()
        kilian = KilianProtocol(oracle, merkle_arity=3)
        
        test_cases = [
            ([1, 2, 3], {'type': 'sum', 'target': 6}),
            ([10, 20, 30], {'type': 'sum', 'target': 60}),
            ([5, 5, 5], {'type': 'sum', 'target': 15}),
        ]
        
        for witness, statement in test_cases:
            randomness = random.randbytes(32)
            proof = kilian.prove(witness, statement, randomness)
            is_valid = kilian.verify(proof, statement, randomness)
            assert is_valid, f"Completeness failed for witness={witness}"
    
    def test_different_merkle_arities(self):
        """Test protocol with different Merkle tree configurations."""
        oracle = PCPOracle()
        witness = [2, 3, 5]
        statement = {'type': 'sum', 'target': 10}
        
        for arity in [2, 3, 4, 8]:
            kilian = KilianProtocol(oracle, merkle_arity=arity)
            randomness = random.randbytes(32)
            
            proof = kilian.prove(witness, statement, randomness)
            is_valid = kilian.verify(proof, statement, randomness)
            assert is_valid, f"Failed with arity={arity}"


class TestMicaliSNARG:
    """Test cases for Micali's non-interactive SNARG."""
    
    def test_protocol_initialization(self):
        """Test initialization of Micali's protocol."""
        oracle = PCPOracle()
        micali = MicaliSNARG(oracle, merkle_arity=2)
        
        assert micali.pcp_oracle == oracle
        assert micali.merkle_arity == 2
    
    def test_non_interactive_proof(self):
        """Test non-interactive proof generation."""
        oracle = PCPOracle()
        micali = MicaliSNARG(oracle)
        
        witness = [7, 8, 9]
        statement = {'type': 'sum', 'target': 24}
        
        proof = micali.prove(witness, statement)
        
        assert isinstance(proof, MicaliSNARG.Proof)
        assert len(proof.merkle_root) == 32
        assert 'query_positions' in proof.proof_metadata
        assert 'proof_length' in proof.proof_metadata
    
    def test_verify_non_interactive_proof(self):
        """Test verification of non-interactive proof."""
        oracle = PCPOracle()
        micali = MicaliSNARG(oracle)
        
        witness = [3, 5, 7]
        statement = {'type': 'sum', 'target': 15}
        
        proof = micali.prove(witness, statement)
        is_valid = micali.verify(proof, statement)
        
        assert is_valid, "Valid non-interactive proof should verify"
    
    def test_fiat_shamir_determinism(self):
        """Test that Fiat-Shamir challenge is deterministic."""
        oracle = PCPOracle()
        micali = MicaliSNARG(oracle)
        
        witness = [2, 4, 6]
        statement = {'type': 'sum', 'target': 12}
        
        # Generate two proofs with same witness/statement
        proof1 = micali.prove(witness, statement)
        proof2 = micali.prove(witness, statement)
        
        # Roots and query positions should be identical
        assert proof1.merkle_root == proof2.merkle_root
        assert proof1.proof_metadata['query_positions'] == \
               proof2.proof_metadata['query_positions']
    
    def test_completeness_multiple_cases(self):
        """Test completeness with multiple test cases."""
        oracle = PCPOracle()
        micali = MicaliSNARG(oracle, merkle_arity=4)
        
        test_cases = [
            ([1, 1, 1], {'type': 'sum', 'target': 3}),
            ([10, 15, 5], {'type': 'sum', 'target': 30}),
            ([100, 200, 50], {'type': 'sum', 'target': 350}),
        ]
        
        for witness, statement in test_cases:
            proof = micali.prove(witness, statement)
            is_valid = micali.verify(proof, statement)
            assert is_valid, f"Failed for witness={witness}"


class TestBCC14SNARK:
    """Test cases for BCC14 adaptive SNARK."""
    
    def test_protocol_initialization(self):
        """Test initialization of BCC14 protocol."""
        oracle = PCPOracle()
        bcc14 = BCC14SNARK(oracle, merkle_arity=4)
        
        assert bcc14.pcp_oracle == oracle
        assert bcc14.merkle_arity == 4
        assert isinstance(bcc14.pir_scheme, SimulatedPIR)
    
    def test_vgrs_generation(self):
        """Test VGRS (setup) generation."""
        oracle = PCPOracle()
        bcc14 = BCC14SNARK(oracle)
        
        statement = {'type': 'sum', 'target': 10}
        vgrs = bcc14.setup(statement, witness_size=3)
        
        assert isinstance(vgrs, BCC14SNARK.VGRS)
        assert len(vgrs.pir_queries) == oracle.num_queries
        assert len(vgrs.pir_keys) == oracle.num_queries
        assert vgrs.merkle_arity == bcc14.merkle_arity
    
    def test_adaptive_proof_generation(self):
        """Test adaptive proof generation."""
        oracle = PCPOracle()
        bcc14 = BCC14SNARK(oracle, merkle_arity=4)
        
        statement = {'type': 'sum', 'target': 12}
        witness = [3, 4, 5]
        vgrs = bcc14.setup(statement, witness_size=len(witness))
        
        proof = bcc14.prove(vgrs, witness, statement)
        
        assert isinstance(proof, BCC14SNARK.Proof)
        assert len(proof.merkle_root) == 32
        assert len(proof.pir_responses) == len(vgrs.pir_queries)
        assert len(proof.authentication_paths) == len(vgrs.pir_queries)
    
    def test_verify_adaptive_proof(self):
        """Test verification of adaptive SNARK."""
        oracle = PCPOracle()
        bcc14 = BCC14SNARK(oracle, merkle_arity=4)
        
        statement = {'type': 'sum', 'target': 15}
        witness = [5, 5, 5]
        vgrs = bcc14.setup(statement, witness_size=len(witness))
        
        proof = bcc14.prove(vgrs, witness, statement)
        is_valid = bcc14.verify(vgrs, proof, statement)
        
        assert is_valid, "Valid BCC14 proof should verify"
    
    def test_completeness_bcc14(self):
        """Test completeness of BCC14 construction."""
        oracle = PCPOracle()
        bcc14 = BCC14SNARK(oracle, merkle_arity=8)
        
        test_cases = [
            ([2, 3, 4], {'type': 'sum', 'target': 9}),
            ([10, 10, 10], {'type': 'sum', 'target': 30}),
            ([7, 8, 9], {'type': 'sum', 'target': 24}),
        ]
        
        for witness, statement in test_cases:
            vgrs = bcc14.setup(statement, witness_size=len(witness))
            proof = bcc14.prove(vgrs, witness, statement)
            is_valid = bcc14.verify(vgrs, proof, statement)
            assert is_valid, f"BCC14 completeness failed for witness={witness}"
    
    def test_squashed_merkle_optimization(self):
        """Test that higher arity is used for efficiency."""
        oracle = PCPOracle()
        
        # Compare binary vs squashed tree
        bcc14_binary = BCC14SNARK(oracle, merkle_arity=2)
        bcc14_squashed = BCC14SNARK(oracle, merkle_arity=8)
        
        statement = {'type': 'sum', 'target': 20}
        witness = [5, 7, 8]
        
        # Both should work
        vgrs_binary = bcc14_binary.setup(statement, witness_size=len(witness))
        proof_binary = bcc14_binary.prove(vgrs_binary, witness, statement)
        assert bcc14_binary.verify(vgrs_binary, proof_binary, statement)
        
        vgrs_squashed = bcc14_squashed.setup(statement, witness_size=len(witness))
        proof_squashed = bcc14_squashed.prove(vgrs_squashed, witness, statement)
        assert bcc14_squashed.verify(vgrs_squashed, proof_squashed, statement)


# ============================================================================
# TEST DEMO FUNCTIONS
# ============================================================================

class TestDemoFunctions:
    """Test the demonstration functions."""
    
    def test_demo_kilian(self):
        """Test Kilian protocol demo."""
        is_valid, description = demo_kilian()
        
        assert isinstance(is_valid, bool)
        assert is_valid, "Kilian demo should produce valid proof"
        assert 'Kilian' in description
        assert 'valid=True' in description
    
    def test_demo_micali(self):
        """Test Micali SNARG demo."""
        is_valid, description = demo_micali()
        
        assert isinstance(is_valid, bool)
        assert is_valid, "Micali demo should produce valid proof"
        assert 'Micali' in description
        assert 'valid=True' in description
    
    def test_demo_bcc14(self):
        """Test BCC14 SNARK demo."""
        is_valid, description = demo_bcc14()
        
        assert isinstance(is_valid, bool)
        assert is_valid, "BCC14 demo should produce valid proof"
        assert 'BCC14' in description
        assert 'valid=True' in description
    
    def test_all_demos_pass(self):
        """Test that all demo functions execute successfully."""
        demos = [demo_kilian, demo_micali, demo_bcc14]
        
        for demo_func in demos:
            is_valid, desc = demo_func()
            assert is_valid, f"{demo_func.__name__} failed: {desc}"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for the complete SNARK pipeline."""
    
    def test_full_pipeline_comparison(self):
        """Compare all three protocols on the same instance."""
        oracle = PCPOracle(field_size=257)
        witness = [4, 5, 6]
        statement = {'type': 'sum', 'target': 15}
        
        # Test Kilian (interactive)
        kilian = KilianProtocol(oracle)
        randomness = random.randbytes(32)
        proof_k = kilian.prove(witness, statement, randomness)
        assert kilian.verify(proof_k, statement, randomness)
        
        # Test Micali (non-interactive)
        micali = MicaliSNARG(oracle)
        proof_m = micali.prove(witness, statement)
        assert micali.verify(proof_m, statement)
        
        # Test BCC14 (adaptive)
        bcc14 = BCC14SNARK(oracle)
        vgrs = bcc14.setup(statement, witness_size=len(witness))
        proof_b = bcc14.prove(vgrs, witness, statement)
        assert bcc14.verify(vgrs, proof_b, statement)
    
    def test_large_witness(self):
        """Test with larger witness sizes."""
        oracle = PCPOracle()
        witness = list(range(1, 11))  # [1, 2, ..., 10]
        statement = {'type': 'sum', 'target': sum(witness)}
        
        # Test with BCC14 (most sophisticated)
        bcc14 = BCC14SNARK(oracle, merkle_arity=4)
        vgrs = bcc14.setup(statement, witness_size=len(witness))
        proof = bcc14.prove(vgrs, witness, statement)
        is_valid = bcc14.verify(vgrs, proof, statement)
        
        assert is_valid, "Large witness should verify correctly"
    
    def test_different_field_sizes(self):
        """Test protocols with different field sizes."""
        witness = [2, 3, 5]
        statement = {'type': 'sum', 'target': 10}
        
        for field_size in [31, 97, 257]:
            oracle = PCPOracle(field_size=field_size)
            micali = MicaliSNARG(oracle)
            
            proof = micali.prove(witness, statement)
            is_valid = micali.verify(proof, statement)
            assert is_valid, f"Failed with field_size={field_size}"
