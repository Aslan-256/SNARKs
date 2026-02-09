"""Unit tests for finite field arithmetic."""

import pytest
from snarks.core.finite_field import FiniteField


class TestFiniteField:
    """Test cases for FiniteField class."""
    
    def test_creation(self):
        """Test field element creation."""
        f = FiniteField(5, 7)
        assert f.value == 5
        assert f.modulus == 7
    
    def test_modular_reduction(self):
        """Test automatic modular reduction."""
        f = FiniteField(10, 7)
        assert f.value == 3  # 10 mod 7 = 3
    
    def test_addition(self):
        """Test field addition."""
        a = FiniteField(5, 7)
        b = FiniteField(4, 7)
        c = a + b
        assert c.value == 2  # (5 + 4) mod 7 = 2
    
    def test_subtraction(self):
        """Test field subtraction."""
        a = FiniteField(3, 7)
        b = FiniteField(5, 7)
        c = a - b
        assert c.value == 5  # (3 - 5) mod 7 = -2 mod 7 = 5
    
    def test_multiplication(self):
        """Test field multiplication."""
        a = FiniteField(3, 7)
        b = FiniteField(4, 7)
        c = a * b
        assert c.value == 5  # (3 * 4) mod 7 = 12 mod 7 = 5
    
    def test_multiplication_by_int(self):
        """Test multiplication by integer."""
        a = FiniteField(3, 7)
        c = a * 4
        assert c.value == 5  # (3 * 4) mod 7 = 5
        
        d = 4 * a
        assert d.value == 5
    
    def test_division(self):
        """Test field division."""
        a = FiniteField(6, 7)
        b = FiniteField(2, 7)
        c = a / b
        assert c.value == 3  # 6/2 = 3 in F_7
    
    def test_inverse(self):
        """Test multiplicative inverse."""
        a = FiniteField(3, 7)
        inv = a.inverse()
        product = a * inv
        assert product.value == 1  # 3 * inv(3) = 1 in F_7
    
    def test_power(self):
        """Test exponentiation."""
        a = FiniteField(2, 7)
        b = a ** 3
        assert b.value == 1  # 2^3 mod 7 = 8 mod 7 = 1
    
    def test_negation(self):
        """Test additive inverse."""
        a = FiniteField(3, 7)
        b = -a
        c = a + b
        assert c.value == 0  # 3 + (-3) = 0 in F_7
    
    def test_equality(self):
        """Test equality comparison."""
        a = FiniteField(3, 7)
        b = FiniteField(3, 7)
        c = FiniteField(4, 7)
        assert a == b
        assert a != c
    
    def test_different_fields_error(self):
        """Test that operations between different fields raise errors."""
        a = FiniteField(3, 7)
        b = FiniteField(3, 11)
        
        with pytest.raises(ValueError):
            _ = a + b
        
        with pytest.raises(ValueError):
            _ = a - b
        
        with pytest.raises(ValueError):
            _ = a * b
    
    def test_division_by_zero(self):
        """Test that division by zero raises error."""
        a = FiniteField(3, 7)
        b = FiniteField(0, 7)
        
        with pytest.raises(ValueError):
            _ = a / b
    
    def test_zero_inverse_error(self):
        """Test that inverse of zero raises error."""
        a = FiniteField(0, 7)
        
        with pytest.raises(ValueError):
            _ = a.inverse()
    
    def test_hash(self):
        """Test that field elements are hashable."""
        a = FiniteField(3, 7)
        b = FiniteField(3, 7)
        c = FiniteField(4, 7)
        
        s = {a, b, c}
        assert len(s) == 2  # a and b are equal, so only 2 unique elements
