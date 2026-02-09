"""
Polynomial implementation over finite fields.

This module provides polynomial arithmetic over finite fields, supporting
evaluation, addition, multiplication, and division operations.
"""

from typing import List, Union
from .finite_field import FiniteField


class Polynomial:
    """
    A polynomial with coefficients in a finite field.
    
    Polynomials are represented as a list of coefficients [a0, a1, a2, ...]
    representing a0 + a1*x + a2*x^2 + ...
    
    Attributes:
        coefficients (List[FiniteField]): Coefficients from lowest to highest degree.
        modulus (int): The field modulus for all coefficients.
    
    Examples:
        >>> # Create polynomial 3 + 2x in F_7
        >>> p = Polynomial([FiniteField(3, 7), FiniteField(2, 7)])
        >>> # Evaluate at x = 4
        >>> p.evaluate(FiniteField(4, 7))
        FiniteField(4, 7)  # 3 + 2*4 = 11 mod 7 = 4
    """
    
    def __init__(self, coefficients: List[FiniteField]):
        """
        Initialize a polynomial with given coefficients.
        
        Args:
            coefficients: List of finite field elements (lowest to highest degree).
        
        Raises:
            ValueError: If coefficients are empty or from different fields.
        """
        if not coefficients:
            raise ValueError("Polynomial must have at least one coefficient")
        
        # Verify all coefficients are from the same field
        modulus = coefficients[0].modulus
        if not all(c.modulus == modulus for c in coefficients):
            raise ValueError("All coefficients must be from the same field")
        
        self.modulus = modulus
        # Remove leading zeros
        self.coefficients = self._remove_leading_zeros(coefficients)
        if not self.coefficients:
            # Zero polynomial
            self.coefficients = [FiniteField(0, modulus)]
    
    @staticmethod
    def _remove_leading_zeros(coefficients: List[FiniteField]) -> List[FiniteField]:
        """Remove leading zero coefficients."""
        while len(coefficients) > 1 and coefficients[-1].value == 0:
            coefficients = coefficients[:-1]
        return coefficients
    
    def degree(self) -> int:
        """
        Get the degree of the polynomial.
        
        Returns:
            The degree (highest power with non-zero coefficient).
        """
        return len(self.coefficients) - 1
    
    def evaluate(self, x: FiniteField) -> FiniteField:
        """
        Evaluate the polynomial at a given point using Horner's method.
        
        Args:
            x: The point at which to evaluate the polynomial.
        
        Returns:
            The value of the polynomial at x.
        
        Raises:
            ValueError: If x is from a different field.
        """
        if x.modulus != self.modulus:
            raise ValueError("Cannot evaluate with value from different field")
        
        # Horner's method: more efficient than naive evaluation
        result = FiniteField(0, self.modulus)
        for coeff in reversed(self.coefficients):
            result = result * x + coeff
        return result
    
    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """
        Add two polynomials.
        
        Args:
            other: Another polynomial with the same field.
        
        Returns:
            The sum of the two polynomials.
        
        Raises:
            ValueError: If the polynomials are over different fields.
        """
        if self.modulus != other.modulus:
            raise ValueError("Cannot add polynomials from different fields")
        
        max_len = max(len(self.coefficients), len(other.coefficients))
        result_coeffs = []
        
        for i in range(max_len):
            a = self.coefficients[i] if i < len(self.coefficients) else FiniteField(0, self.modulus)
            b = other.coefficients[i] if i < len(other.coefficients) else FiniteField(0, self.modulus)
            result_coeffs.append(a + b)
        
        return Polynomial(result_coeffs)
    
    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """
        Subtract two polynomials.
        
        Args:
            other: Another polynomial with the same field.
        
        Returns:
            The difference of the two polynomials.
        
        Raises:
            ValueError: If the polynomials are over different fields.
        """
        if self.modulus != other.modulus:
            raise ValueError("Cannot subtract polynomials from different fields")
        
        max_len = max(len(self.coefficients), len(other.coefficients))
        result_coeffs = []
        
        for i in range(max_len):
            a = self.coefficients[i] if i < len(self.coefficients) else FiniteField(0, self.modulus)
            b = other.coefficients[i] if i < len(other.coefficients) else FiniteField(0, self.modulus)
            result_coeffs.append(a - b)
        
        return Polynomial(result_coeffs)
    
    def __mul__(self, other: Union['Polynomial', FiniteField, int]) -> 'Polynomial':
        """
        Multiply polynomial by another polynomial or scalar.
        
        Args:
            other: A polynomial, finite field element, or integer.
        
        Returns:
            The product.
        
        Raises:
            ValueError: If multiplying with incompatible field.
        """
        if isinstance(other, int):
            other = FiniteField(other, self.modulus)
        
        if isinstance(other, FiniteField):
            # Scalar multiplication
            if other.modulus != self.modulus:
                raise ValueError("Cannot multiply with element from different field")
            new_coeffs = [c * other for c in self.coefficients]
            return Polynomial(new_coeffs)
        
        if isinstance(other, Polynomial):
            # Polynomial multiplication
            if self.modulus != other.modulus:
                raise ValueError("Cannot multiply polynomials from different fields")
            
            result_len = len(self.coefficients) + len(other.coefficients) - 1
            result_coeffs = [FiniteField(0, self.modulus) for _ in range(result_len)]
            
            for i, a in enumerate(self.coefficients):
                for j, b in enumerate(other.coefficients):
                    result_coeffs[i + j] = result_coeffs[i + j] + (a * b)
            
            return Polynomial(result_coeffs)
        
        raise TypeError(f"Cannot multiply Polynomial with {type(other)}")
    
    def __rmul__(self, other: Union[FiniteField, int]) -> 'Polynomial':
        """Support for scalar * Polynomial."""
        return self.__mul__(other)
    
    def __truediv__(self, other: Union[FiniteField, int]) -> 'Polynomial':
        """
        Divide polynomial by a scalar.
        
        Args:
            other: A finite field element or integer.
        
        Returns:
            The quotient polynomial.
        """
        if isinstance(other, int):
            other = FiniteField(other, self.modulus)
        
        if isinstance(other, FiniteField):
            if other.modulus != self.modulus:
                raise ValueError("Cannot divide by element from different field")
            inv = other.inverse()
            return self * inv
        
        raise TypeError(f"Cannot divide Polynomial by {type(other)}")
    
    def __eq__(self, other: object) -> bool:
        """Check equality of two polynomials."""
        if not isinstance(other, Polynomial):
            return False
        return (self.modulus == other.modulus and 
                self.coefficients == other.coefficients)
    
    def __repr__(self) -> str:
        """String representation of the polynomial."""
        if not self.coefficients:
            return "Polynomial([])"
        coeffs_repr = ", ".join(repr(c) for c in self.coefficients)
        return f"Polynomial([{coeffs_repr}])"
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        if len(self.coefficients) == 1:
            return str(self.coefficients[0].value)
        
        terms = []
        for i, coeff in enumerate(self.coefficients):
            if coeff.value == 0:
                continue
            if i == 0:
                terms.append(str(coeff.value))
            elif i == 1:
                if coeff.value == 1:
                    terms.append("x")
                else:
                    terms.append(f"{coeff.value}x")
            else:
                if coeff.value == 1:
                    terms.append(f"x^{i}")
                else:
                    terms.append(f"{coeff.value}x^{i}")
        
        if not terms:
            return "0"
        return " + ".join(terms) + f" (mod {self.modulus})"
    
    @classmethod
    def zero(cls, modulus: int) -> 'Polynomial':
        """
        Create a zero polynomial.
        
        Args:
            modulus: The field modulus.
        
        Returns:
            The zero polynomial.
        """
        return cls([FiniteField(0, modulus)])
    
    @classmethod
    def constant(cls, value: int, modulus: int) -> 'Polynomial':
        """
        Create a constant polynomial.
        
        Args:
            value: The constant value.
            modulus: The field modulus.
        
        Returns:
            A constant polynomial.
        """
        return cls([FiniteField(value, modulus)])
    
    @classmethod
    def monomial(cls, degree: int, coefficient: int, modulus: int) -> 'Polynomial':
        """
        Create a monomial (single term) polynomial.
        
        Args:
            degree: The degree of the monomial.
            coefficient: The coefficient value.
            modulus: The field modulus.
        
        Returns:
            A monomial polynomial of the form coefficient * x^degree.
        """
        coeffs = [FiniteField(0, modulus) for _ in range(degree + 1)]
        coeffs[degree] = FiniteField(coefficient, modulus)
        return cls(coeffs)
