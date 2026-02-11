"""
Tests for commitment schemes.

Tests KZG polynomial commitments and Pedersen vector commitments.
"""

import unittest
from snarks.primitives import (
    KZGCommitment,
    PedersenVectorCommitment,
    SimulatedBilinearGroup
)


class TestSimulatedBilinearGroup(unittest.TestCase):
    """Test simulated bilinear group operations."""
    
    def test_group_initialization(self):
        """Test group initialization."""
        p = 101
        group = SimulatedBilinearGroup(field_modulus=p)
        
        self.assertEqual(group.field_modulus, p)
    
    def test_g1_multiplication(self):
        """Test G1 scalar multiplication."""
        group = SimulatedBilinearGroup(field_modulus=101)
        
        # [3]_1
        result = group.g1_mul(3, base=1)
        self.assertEqual(result, 3)
        
        # [5]_1 * 7 = [35]_1
        result = group.g1_mul(7, base=5)
        self.assertEqual(result, (5 * 7) % 101)
    
    def test_g1_addition(self):
        """Test G1 addition."""
        group = SimulatedBilinearGroup(field_modulus=101)
        
        a = group.g1_mul(3)
        b = group.g1_mul(5)
        result = group.g1_add(a, b)
        
        self.assertEqual(result, (3 + 5) % 101)
    
    def test_pairing_bilinearity(self):
        """Test pairing bilinearity property."""
        group = SimulatedBilinearGroup(field_modulus=101)
        
        # e([a]_1, [b]_2) should equal e([1]_1, [ab]_2)
        a, b = 3, 5
        
        lhs = group.pairing(group.g1_mul(a), group.g2_mul(b))
        rhs = group.pairing(group.g1_mul(1), group.g2_mul((a * b) % 101))
        
        # In simulation: both should equal a*b mod p
        self.assertEqual(lhs, rhs)


class TestKZGCommitment(unittest.TestCase):
    """Test KZG polynomial commitment scheme."""
    
    def setUp(self):
        """Setup KZG for tests."""
        self.field_modulus = 101
        self.kzg = KZGCommitment(field_modulus=self.field_modulus)
        self.setup = self.kzg.setup(max_degree=5)
    
    def test_setup_generation(self):
        """Test trusted setup generation."""
        self.assertEqual(len(self.setup.powers_of_tau_g1), 6)  # 0 to 5
        self.assertIsNotNone(self.setup.tau_g2)
        self.assertEqual(self.setup.max_degree, 5)
        self.assertEqual(self.setup.field_modulus, self.field_modulus)
    
    def test_polynomial_commitment(self):
        """Test committing to a polynomial."""
        # Polynomial f(X) = 3 + 7X + 2X²
        poly = [3, 7, 2]
        
        commitment = self.kzg.commit(poly, self.setup)
        
        # Commitment should be a valid field element
        self.assertIsInstance(commitment, int)
        self.assertGreaterEqual(commitment, 0)
        self.assertLess(commitment, self.field_modulus)
    
    def test_polynomial_opening(self):
        """Test opening polynomial at a point."""
        poly = [3, 7, 2]  # 3 + 7X + 2X²
        x = 5
        
        # Evaluate: f(5) = 3 + 35 + 50 = 88
        expected_y = (3 + 7*5 + 2*25) % self.field_modulus
        
        y, proof = self.kzg.open(poly, x, self.setup)
        
        self.assertEqual(y, expected_y)
        self.assertIsInstance(proof, int)
    
    def test_verification(self):
        """Test KZG verification."""
        poly = [3, 7, 2]
        commitment = self.kzg.commit(poly, self.setup)
        
        x = 5
        y, proof = self.kzg.open(poly, x, self.setup)
        
        # Verify should succeed
        is_valid = self.kzg.verify(commitment, x, y, proof, self.setup)
        self.assertTrue(is_valid)
    
    def test_verification_fails_wrong_value(self):
        """Test that verification fails with wrong value."""
        poly = [3, 7, 2]
        commitment = self.kzg.commit(poly, self.setup)
        
        x = 5
        y, proof = self.kzg.open(poly, x, self.setup)
        
        # Try to verify with wrong value
        wrong_y = (y + 1) % self.field_modulus
        is_valid = self.kzg.verify(commitment, x, wrong_y, proof, self.setup)
        self.assertFalse(is_valid)
    
    def test_constant_polynomial(self):
        """Test commitment to constant polynomial."""
        poly = [42]  # f(X) = 42
        commitment = self.kzg.commit(poly, self.setup)
        
        # At any point, should evaluate to 42
        for x in [0, 1, 5, 10]:
            y, proof = self.kzg.open(poly, x, self.setup)
            self.assertEqual(y, 42)
            
            is_valid = self.kzg.verify(commitment, x, y, proof, self.setup)
            self.assertTrue(is_valid)
    
    def test_zero_polynomial(self):
        """Test commitment to zero polynomial."""
        poly = [0, 0, 0]
        commitment = self.kzg.commit(poly, self.setup)
        
        x = 7
        y, proof = self.kzg.open(poly, x, self.setup)
        
        self.assertEqual(y, 0)
        is_valid = self.kzg.verify(commitment, x, y, proof, self.setup)
        self.assertTrue(is_valid)
    
    def test_degree_exceeds_setup(self):
        """Test that high-degree polynomial fails."""
        # Polynomial of degree 10 (exceeds max_degree=5)
        poly = list(range(11))
        
        with self.assertRaises(ValueError):
            self.kzg.commit(poly, self.setup)
    
    def test_batch_verification(self):
        """Test batch verification of multiple openings."""
        poly1 = [1, 2, 3]
        poly2 = [4, 5, 6]
        
        c1 = self.kzg.commit(poly1, self.setup)
        c2 = self.kzg.commit(poly2, self.setup)
        
        x1, x2 = 2, 3
        y1, p1 = self.kzg.open(poly1, x1, self.setup)
        y2, p2 = self.kzg.open(poly2, x2, self.setup)
        
        # Batch verify
        is_valid = self.kzg.batch_verify(
            [c1, c2], [x1, x2], [y1, y2], [p1, p2],
            self.setup
        )
        self.assertTrue(is_valid)


class TestPedersenVectorCommitment(unittest.TestCase):
    """Test Pedersen vector commitment scheme."""
    
    def setUp(self):
        """Setup Pedersen for tests."""
        self.field_modulus = 101
        self.pedersen = PedersenVectorCommitment()
        self.setup = self.pedersen.setup(
            vector_size=5, 
            field_modulus=self.field_modulus
        )
    
    def test_setup_generation(self):
        """Test Pedersen setup."""
        self.assertEqual(len(self.setup.generators), 5)
        self.assertIsNotNone(self.setup.h)
        self.assertEqual(self.setup.field_modulus, self.field_modulus)
    
    def test_vector_commitment(self):
        """Test committing to a vector."""
        vector = [1, 2, 3, 4, 5]
        randomness = 42
        
        commitment = self.pedersen.commit(vector, self.setup, randomness)
        
        self.assertIsInstance(commitment, int)
        self.assertGreaterEqual(commitment, 0)
    
    def test_commitment_opening_and_verification(self):
        """Test opening and verifying commitment."""
        vector = [10, 20, 30, 40, 50]
        randomness = 12345
        
        commitment = self.pedersen.commit(vector, self.setup, randomness)
        opening = self.pedersen.open(vector, commitment, randomness)
        
        is_valid = self.pedersen.verify(commitment, vector, opening, self.setup)
        self.assertTrue(is_valid)
    
    def test_verification_fails_wrong_vector(self):
        """Test that wrong vector fails verification."""
        vector = [1, 2, 3, 4, 5]
        randomness = 42
        
        commitment = self.pedersen.commit(vector, self.setup, randomness)
        
        # Try to open with wrong vector
        wrong_vector = [1, 2, 3, 4, 6]
        opening = (wrong_vector, randomness)
        
        is_valid = self.pedersen.verify(commitment, wrong_vector, opening, self.setup)
        self.assertFalse(is_valid)
    
    def test_hiding_property(self):
        """Test that commitments hide the vector (with randomness)."""
        vector = [1, 2, 3, 4, 5]
        
        # Same vector, different randomness → different commitments
        c1 = self.pedersen.commit(vector, self.setup, randomness=10)
        c2 = self.pedersen.commit(vector, self.setup, randomness=20)
        
        self.assertNotEqual(c1, c2)
    
    def test_zero_vector(self):
        """Test commitment to zero vector."""
        vector = [0, 0, 0, 0, 0]
        randomness = 99
        
        commitment = self.pedersen.commit(vector, self.setup, randomness)
        opening = self.pedersen.open(vector, commitment, randomness)
        
        is_valid = self.pedersen.verify(commitment, vector, opening, self.setup)
        self.assertTrue(is_valid)
    
    def test_wrong_vector_size(self):
        """Test that wrong sized vector fails."""
        vector = [1, 2, 3]  # Size 3, but setup is for 5
        
        with self.assertRaises(ValueError):
            self.pedersen.commit(vector, self.setup)


if __name__ == '__main__':
    unittest.main()
