"""Unit tests for PIOP proof system."""

import pytest
from snarks.proofs.piop import PIOP, PIOPSetup, PIOPProof, PIOracle, piop_example
from snarks.core.polynomial import Polynomial
from snarks.core.finite_field import FiniteField


class TestPIOP:
    """Test cases for PIOP proof system."""
    
    def test_setup(self):
        """Test PIOP setup."""
        setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
        assert setup.modulus == 97
        assert setup.num_variables == 3
        assert setup.poly_degree == 3
    
    def test_oracle_creation(self):
        """Test polynomial oracle creation."""
        coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
        poly = Polynomial(coeffs)
        oracle = PIOracle(poly)
        
        assert oracle.polynomial == poly
        assert oracle.commitment.modulus == 7
    
    def test_oracle_query(self):
        """Test oracle querying."""
        coeffs = [FiniteField(1, 7), FiniteField(2, 7)]
        poly = Polynomial(coeffs)  # 1 + 2x
        oracle = PIOracle(poly)
        
        # Query at x=3: 1 + 2*3 = 7 mod 7 = 0
        result = oracle.query(FiniteField(3, 7))
        assert result.value == 0
    
    def test_prove(self):
        """Test proof generation."""
        setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
        witness = [3, 4, 5]
        statement = [60]
        
        proof = PIOP.prove(setup, witness, statement)
        assert isinstance(proof, PIOPProof)
        assert 'witness' in proof.oracles
        assert 'trace' in proof.oracles
        assert 'constraint' in proof.oracles
    
    def test_verify_valid_proof(self):
        """Test verification of valid proof."""
        setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
        witness = [3, 4, 5]
        statement = [60]
        
        proof = PIOP.prove(setup, witness, statement)
        is_valid = PIOP.verify(setup, proof, statement, num_queries=3)
        assert is_valid
    
    def test_interactive_protocol(self):
        """Test full interactive protocol."""
        setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
        witness = [3, 4, 5]
        statement = [60]
        
        proof, is_valid = PIOP.interactive_prove_verify(setup, witness, statement)
        assert isinstance(proof, PIOPProof)
        assert is_valid
    
    def test_example(self):
        """Test the example function."""
        setup, proof, statement, is_valid = piop_example()
        
        assert isinstance(setup, PIOPSetup)
        assert isinstance(proof, PIOPProof)
        assert len(statement) > 0
        assert is_valid
    
    def test_different_modulus(self):
        """Test with different field sizes."""
        for modulus in [7, 31, 97]:
            setup = PIOP.setup(modulus=modulus, num_variables=2, poly_degree=2)
            witness = [2, 3]
            statement = [6]
            
            proof, is_valid = PIOP.interactive_prove_verify(setup, witness, statement)
            assert is_valid
    
    def test_different_poly_degree(self):
        """Test with different polynomial degrees."""
        for degree in [2, 4, 6]:
            setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=degree)
            witness = [3, 4, 5]
            statement = [60]
            
            proof = PIOP.prove(setup, witness, statement)
            assert all(oracle.polynomial.degree() <= degree 
                      for oracle in proof.oracles.values())
