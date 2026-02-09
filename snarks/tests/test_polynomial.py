"""Unit tests for polynomial arithmetic."""

import pytest
from snarks.core.finite_field import FiniteField
from snarks.core.polynomial import Polynomial


class TestPolynomial:
    """Test cases for Polynomial class."""
    
    def test_creation(self):
        """Test polynomial creation."""
        coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
        p = Polynomial(coeffs)
        assert len(p.coefficients) == 3
        assert p.modulus == 7
    
    def test_degree(self):
        """Test degree calculation."""
        coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
        p = Polynomial(coeffs)
        assert p.degree() == 2  # Degree is highest power
    
    def test_remove_leading_zeros(self):
        """Test that leading zeros are removed."""
        coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(0, 7)]
        p = Polynomial(coeffs)
        assert len(p.coefficients) == 2
        assert p.degree() == 1
    
    def test_evaluation(self):
        """Test polynomial evaluation."""
        # p(x) = 1 + 2x + 3x^2
        coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
        p = Polynomial(coeffs)
        
        # Evaluate at x = 2: 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17 mod 7 = 3
        x = FiniteField(2, 7)
        result = p.evaluate(x)
        assert result.value == 3
    
    def test_addition(self):
        """Test polynomial addition."""
        # p(x) = 1 + 2x
        p = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        # q(x) = 3 + 4x
        q = Polynomial([FiniteField(3, 7), FiniteField(4, 7)])
        
        # (p + q)(x) = 4 + 6x
        r = p + q
        assert r.coefficients[0].value == 4
        assert r.coefficients[1].value == 6
    
    def test_addition_different_degrees(self):
        """Test addition of polynomials with different degrees."""
        # p(x) = 1 + 2x
        p = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        # q(x) = 3 + 4x + 5x^2
        q = Polynomial([FiniteField(3, 7), FiniteField(4, 7), FiniteField(5, 7)])
        
        r = p + q
        assert len(r.coefficients) == 3
        assert r.coefficients[0].value == 4
        assert r.coefficients[1].value == 6
        assert r.coefficients[2].value == 5
    
    def test_subtraction(self):
        """Test polynomial subtraction."""
        # p(x) = 5 + 6x
        p = Polynomial([FiniteField(5, 7), FiniteField(6, 7)])
        # q(x) = 2 + 3x
        q = Polynomial([FiniteField(2, 7), FiniteField(3, 7)])
        
        # (p - q)(x) = 3 + 3x
        r = p - q
        assert r.coefficients[0].value == 3
        assert r.coefficients[1].value == 3
    
    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        # p(x) = 2 + 3x
        p = Polynomial([FiniteField(2, 7), FiniteField(3, 7)])
        
        # 2 * p(x) = 4 + 6x
        r = p * 2
        assert r.coefficients[0].value == 4
        assert r.coefficients[1].value == 6
        
        # Test reverse multiplication
        r2 = 2 * p
        assert r2.coefficients[0].value == 4
    
    def test_polynomial_multiplication(self):
        """Test polynomial multiplication."""
        # p(x) = 1 + 2x
        p = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        # q(x) = 3 + 4x
        q = Polynomial([FiniteField(3, 7), FiniteField(4, 7)])
        
        # (p * q)(x) = 3 + 10x + 8x^2 = 3 + 3x + 1x^2 (mod 7)
        r = p * q
        assert r.coefficients[0].value == 3
        assert r.coefficients[1].value == 3  # 10 mod 7 = 3
        assert r.coefficients[2].value == 1  # 8 mod 7 = 1
    
    def test_division_by_scalar(self):
        """Test division by scalar."""
        # p(x) = 4 + 6x
        p = Polynomial([FiniteField(4, 7), FiniteField(6, 7)])
        
        # p(x) / 2 = 2 + 3x (since 2^-1 = 4 in F_7)
        r = p / 2
        assert r.coefficients[0].value == 2
        assert r.coefficients[1].value == 3
    
    def test_equality(self):
        """Test polynomial equality."""
        p = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        q = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        r = Polynomial([FiniteField(1, 7), FiniteField(3, 7)])
        
        assert p == q
        assert p != r
    
    def test_zero_polynomial(self):
        """Test zero polynomial."""
        p = Polynomial.zero(7)
        assert p.degree() == 0
        assert p.coefficients[0].value == 0
    
    def test_constant_polynomial(self):
        """Test constant polynomial."""
        p = Polynomial.constant(5, 7)
        assert p.degree() == 0
        assert p.coefficients[0].value == 5
    
    def test_monomial(self):
        """Test monomial creation."""
        # 3x^2
        p = Polynomial.monomial(2, 3, 7)
        assert p.degree() == 2
        assert p.coefficients[0].value == 0
        assert p.coefficients[1].value == 0
        assert p.coefficients[2].value == 3
    
    def test_empty_coefficients_error(self):
        """Test that empty coefficients raise error."""
        with pytest.raises(ValueError):
            _ = Polynomial([])
    
    def test_different_fields_error(self):
        """Test that operations between different fields raise errors."""
        p = Polynomial([FiniteField(1, 7), FiniteField(2, 7)])
        q = Polynomial([FiniteField(1, 11), FiniteField(2, 11)])
        
        with pytest.raises(ValueError):
            _ = p + q
        
        with pytest.raises(ValueError):
            _ = p - q
        
        with pytest.raises(ValueError):
            _ = p * q
