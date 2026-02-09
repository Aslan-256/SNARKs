"""Unit tests for PCP proof system."""

import pytest
from snarks.proofs.pcp import PCP, PCPSetup, PCPProof, pcp_example


class TestPCP:
    """Test cases for PCP proof system."""
    
    def test_setup(self):
        """Test PCP setup."""
        setup = PCP.setup(modulus=97, constraint_degree=2)
        assert setup.modulus == 97
        assert setup.constraint_degree == 2
        assert setup.num_queries == 3
    
    def test_prove(self):
        """Test proof generation."""
        setup = PCP.setup(modulus=97)
        witness = [3, 4, 5]
        statement = [12]
        
        proof = PCP.prove(setup, witness, statement)
        assert isinstance(proof, PCPProof)
        assert len(proof.proof_string) > 0
        assert all(elem.modulus == 97 for elem in proof.proof_string)
    
    def test_verify_valid_proof(self):
        """Test verification of valid proof."""
        setup = PCP.setup(modulus=97)
        witness = [3, 4, 5]
        statement = [12]
        
        proof = PCP.prove(setup, witness, statement)
        is_valid = PCP.verify(setup, proof, statement)
        assert is_valid
    
    def test_query(self):
        """Test proof querying."""
        setup = PCP.setup(modulus=97)
        witness = [3, 4]
        statement = [7]
        
        proof = PCP.prove(setup, witness, statement)
        positions = [0, 1]
        results = proof.query(positions)
        
        assert len(results) == 2
        assert all(elem.modulus == 97 for elem in results)
    
    def test_example(self):
        """Test the example function."""
        setup, proof, statement = pcp_example()
        
        assert isinstance(setup, PCPSetup)
        assert isinstance(proof, PCPProof)
        assert len(statement) > 0
        
        # Verify the example proof
        is_valid = PCP.verify(setup, proof, statement)
        assert is_valid
    
    def test_different_modulus(self):
        """Test with different field sizes."""
        for modulus in [7, 31, 97]:
            setup = PCP.setup(modulus=modulus)
            witness = [2, 3]
            statement = [5]
            
            proof = PCP.prove(setup, witness, statement)
            is_valid = PCP.verify(setup, proof, statement)
            assert is_valid
