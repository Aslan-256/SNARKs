"""
Finite Field implementation for modular arithmetic.

This module provides a simple implementation of finite field arithmetic
over prime fields F_p where p is a prime number.
"""

from typing import Union


class FiniteField:
    """
    A finite field element in F_p (field of integers modulo a prime p).
    
    This class represents elements in a finite field and supports standard
    arithmetic operations (addition, subtraction, multiplication, division)
    with automatic modular reduction.
    
    Attributes:
        value (int): The integer value of this field element (0 <= value < modulus).
        modulus (int): The prime modulus defining the field.
    
    Examples:
        >>> field_elem = FiniteField(5, 7)  # 5 in F_7
        >>> field_elem + FiniteField(3, 7)  # 8 mod 7 = 1 in F_7
        FiniteField(1, 7)
    """
    
    def __init__(self, value: int, modulus: int):
        """
        Initialize a finite field element.
        
        Args:
            value: The integer value to represent in the field.
            modulus: The prime modulus of the field.
        
        Note:
            The value is automatically reduced modulo the modulus.
        """
        self.modulus = modulus
        self.value = value % modulus
    
    def __add__(self, other: 'FiniteField') -> 'FiniteField':
        """
        Add two finite field elements.
        
        Args:
            other: Another finite field element with the same modulus.
        
        Returns:
            The sum of the two elements in the field.
        
        Raises:
            ValueError: If the moduli don't match.
        """
        if self.modulus != other.modulus:
            raise ValueError("Cannot add elements from different fields")
        return FiniteField((self.value + other.value) % self.modulus, self.modulus)
    
    def __sub__(self, other: 'FiniteField') -> 'FiniteField':
        """
        Subtract two finite field elements.
        
        Args:
            other: Another finite field element with the same modulus.
        
        Returns:
            The difference of the two elements in the field.
        
        Raises:
            ValueError: If the moduli don't match.
        """
        if self.modulus != other.modulus:
            raise ValueError("Cannot subtract elements from different fields")
        return FiniteField((self.value - other.value) % self.modulus, self.modulus)
    
    def __mul__(self, other: Union['FiniteField', int]) -> 'FiniteField':
        """
        Multiply two finite field elements or multiply by an integer.
        
        Args:
            other: Another finite field element or an integer.
        
        Returns:
            The product in the field.
        
        Raises:
            ValueError: If multiplying field elements with different moduli.
        """
        if isinstance(other, int):
            return FiniteField((self.value * other) % self.modulus, self.modulus)
        if self.modulus != other.modulus:
            raise ValueError("Cannot multiply elements from different fields")
        return FiniteField((self.value * other.value) % self.modulus, self.modulus)
    
    def __rmul__(self, other: int) -> 'FiniteField':
        """Support for integer * FiniteField."""
        return self.__mul__(other)
    
    def __truediv__(self, other: 'FiniteField') -> 'FiniteField':
        """
        Divide two finite field elements.
        
        Division is performed by multiplying by the multiplicative inverse.
        
        Args:
            other: Another finite field element with the same modulus.
        
        Returns:
            The quotient in the field.
        
        Raises:
            ValueError: If the moduli don't match or if dividing by zero.
        """
        if self.modulus != other.modulus:
            raise ValueError("Cannot divide elements from different fields")
        if other.value == 0:
            raise ValueError("Cannot divide by zero")
        # Multiply by the multiplicative inverse
        inv = other.inverse()
        return self * inv
    
    def __pow__(self, exponent: int) -> 'FiniteField':
        """
        Raise a finite field element to an integer power.
        
        Uses modular exponentiation for efficiency.
        
        Args:
            exponent: The integer exponent.
        
        Returns:
            The result of raising this element to the given power.
        """
        result = pow(self.value, exponent, self.modulus)
        return FiniteField(result, self.modulus)
    
    def __neg__(self) -> 'FiniteField':
        """
        Compute the additive inverse (negation) of this element.
        
        Returns:
            The additive inverse in the field.
        """
        return FiniteField((-self.value) % self.modulus, self.modulus)
    
    def inverse(self) -> 'FiniteField':
        """
        Compute the multiplicative inverse of this element.
        
        Uses the Extended Euclidean Algorithm to find the modular inverse.
        
        Returns:
            The multiplicative inverse in the field.
        
        Raises:
            ValueError: If this element is zero (has no inverse).
        """
        if self.value == 0:
            raise ValueError("Zero has no multiplicative inverse")
        # Use Extended Euclidean Algorithm
        inv = self._extended_gcd(self.value, self.modulus)[0]
        return FiniteField(inv % self.modulus, self.modulus)
    
    @staticmethod
    def _extended_gcd(a: int, b: int) -> tuple[int, int]:
        """
        Extended Euclidean Algorithm.
        
        Computes integers x, y such that ax + by = gcd(a, b).
        
        Args:
            a: First integer.
            b: Second integer.
        
        Returns:
            Tuple (x, y) where ax + by = gcd(a, b).
        """
        if a == 0:
            return 0, 1
        x1, y1 = FiniteField._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return x, y
    
    def __eq__(self, other: object) -> bool:
        """Check equality of two finite field elements."""
        if not isinstance(other, FiniteField):
            return False
        return self.value == other.value and self.modulus == other.modulus
    
    def __ne__(self, other: object) -> bool:
        """Check inequality of two finite field elements."""
        return not self.__eq__(other)
    
    def __repr__(self) -> str:
        """String representation of the finite field element."""
        return f"FiniteField({self.value}, {self.modulus})"
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        return f"{self.value} (mod {self.modulus})"
    
    def __hash__(self) -> int:
        """Hash function for use in sets and dictionaries."""
        return hash((self.value, self.modulus))
