"""Unit tests for QAP proof system."""

import pytest
from snarks.proofs.qap import QAP, QAPSetup, QAPProof, qap_example
from snarks.core.finite_field import FiniteField


class TestQAP:
    """Test cases for QAP proof system."""
    
    def test_setup(self):
        """Test QAP setup."""
        setup = QAP.setup(modulus=97, circuit_size=3)
        assert setup.modulus == 97
        assert setup.qap_instance is not None
        assert len(setup.qap_instance.A_polys) == 4  # 1 constant + 3 variables
    
    def test_prove(self):
        """Test proof generation."""
        setup = QAP.setup(modulus=97)
        witness = [1, 3, 4, 12]  # 1, x=3, y=4, z=12
        
        proof = QAP.prove(setup, witness)
        assert isinstance(proof, QAPProof)
        assert len(proof.assignment) == len(witness)
    
    def test_verify_valid_proof(self):
        """Test verification of valid proof."""
        setup = QAP.setup(modulus=97)
        witness = [1, 3, 4, 12]
        public_inputs = [1, 12]
        
        proof = QAP.prove(setup, witness)
        is_valid = QAP.verify(setup, proof, public_inputs)
        assert is_valid
    
    def test_example(self):
        """Test the example function."""
        setup, proof, public_inputs = qap_example()
        
        assert isinstance(setup, QAPSetup)
        assert isinstance(proof, QAPProof)
        assert len(public_inputs) > 0
        
        # Verify the example proof
        is_valid = QAP.verify(setup, proof, public_inputs)
        assert is_valid
    
    def test_create_circuit(self):
        """Test circuit creation helper."""
        setup = QAP.create_circuit_for_equation(modulus=97)
        assert isinstance(setup, QAPSetup)
        assert setup.modulus == 97
    
    def test_different_modulus(self):
        """Test with different field sizes."""
        for modulus in [7, 31, 97]:
            setup = QAP.setup(modulus=modulus)
            witness = [1, 2, 3, 6]  # 1, x=2, y=3, z=6
            public_inputs = [1, 6]
            
            proof = QAP.prove(setup, witness)
            is_valid = QAP.verify(setup, proof, public_inputs)
            assert is_valid
