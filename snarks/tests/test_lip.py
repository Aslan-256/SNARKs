"""Unit tests for LIP proof system."""

import pytest
from snarks.proofs.lip import LIP, LIPSetup, LIPProof, lip_example


class TestLIP:
    """Test cases for LIP proof system."""
    
    def test_setup(self):
        """Test LIP setup."""
        setup = LIP.setup(modulus=97, num_variables=3, num_rounds=2)
        assert setup.modulus == 97
        assert setup.num_variables == 3
        assert setup.num_rounds == 2
    
    def test_prove(self):
        """Test proof generation."""
        setup = LIP.setup(modulus=97, num_variables=3)
        witness = [3, 4, 5]
        statement = [12]
        
        # Provide fixed challenges for deterministic testing
        challenges = [[1, 2, 3], [4, 5, 6]]
        proof = LIP.prove(setup, witness, statement, challenges)
        
        assert isinstance(proof, LIPProof)
        assert len(proof.responses) == setup.num_rounds
        assert len(proof.commitment) > 0
    
    def test_verify_valid_proof(self):
        """Test verification of valid proof."""
        setup = LIP.setup(modulus=97, num_variables=3)
        witness = [3, 4, 5]
        statement = [12]
        
        challenges = [[1, 2, 3], [4, 5, 6]]
        proof = LIP.prove(setup, witness, statement, challenges)
        is_valid = LIP.verify(setup, proof, statement, challenges)
        assert is_valid
    
    def test_interactive_protocol(self):
        """Test full interactive protocol."""
        setup = LIP.setup(modulus=97, num_variables=3)
        witness = [3, 4, 5]
        statement = [12]
        
        proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
        assert isinstance(proof, LIPProof)
        assert is_valid
    
    def test_example(self):
        """Test the example function."""
        setup, proof, statement, is_valid = lip_example()
        
        assert isinstance(setup, LIPSetup)
        assert isinstance(proof, LIPProof)
        assert len(statement) > 0
        assert is_valid
    
    def test_different_modulus(self):
        """Test with different field sizes."""
        for modulus in [7, 31, 97]:
            setup = LIP.setup(modulus=modulus, num_variables=2)
            witness = [2, 3]
            statement = [5]
            
            proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
            assert is_valid
    
    def test_different_num_rounds(self):
        """Test with different numbers of rounds."""
        for num_rounds in [1, 3, 5]:
            setup = LIP.setup(modulus=97, num_variables=3, num_rounds=num_rounds)
            witness = [3, 4, 5]
            statement = [12]
            
            proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
            assert len(proof.responses) == num_rounds
            assert is_valid
