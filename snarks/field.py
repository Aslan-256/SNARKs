"""
snarks.field – Finite-field arithmetic for zk-STARKs.

Mathematical background
-----------------------
A **prime field** F_p is the set {0, 1, …, p-1} equipped with addition and
multiplication modulo a prime *p*.  Every non-zero element has a unique
multiplicative inverse (by Fermat's little theorem: a^{-1} = a^{p-2} mod p).

For STARKs we need a field whose multiplicative group contains large
two-power-order subgroups so that Number Theoretic Transforms (NTTs) can run
efficiently.  The classic "Goldilocks" prime  p = 2^{64} - 2^{32} + 1  is one
such choice, but for *pedagogical simplicity* we use a slightly smaller prime

    p = 3 * 2^30 + 1  =  3221225473

whose multiplicative group has order  p - 1 = 3 · 2^30.  This gives us
subgroups of order 2^k for every k ≤ 30 - more than enough for our toy
examples.

The module is designed around an **Abstract Base Class** `BaseField` so that
alternative fields (binary towers, extension fields, etc.) can be plugged in
without touching the rest of the stack.
"""

from __future__ import annotations

import abc
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Abstract base class – swap this to change the underlying field
# ---------------------------------------------------------------------------

class BaseField(abc.ABC):
    """Interface that every field implementation must satisfy."""

    @abc.abstractmethod
    def __init__(self, value: int) -> None: ...

    # -- Arithmetic ---------------------------------------------------------
    @abc.abstractmethod
    def __add__(self, other: Any) -> "BaseField": ...

    @abc.abstractmethod
    def __sub__(self, other: Any) -> "BaseField": ...

    @abc.abstractmethod
    def __mul__(self, other: Any) -> "BaseField": ...

    @abc.abstractmethod
    def __truediv__(self, other: Any) -> "BaseField": ...

    @abc.abstractmethod
    def __pow__(self, exp: int) -> "BaseField": ...

    @abc.abstractmethod
    def __neg__(self) -> "BaseField": ...

    @abc.abstractmethod
    def inverse(self) -> "BaseField": ...

    # -- Comparison & hashing -----------------------------------------------
    @abc.abstractmethod
    def __eq__(self, other: object) -> bool: ...

    @abc.abstractmethod
    def __hash__(self) -> int: ...

    @abc.abstractmethod
    def __repr__(self) -> str: ...

    # -- Utilities ----------------------------------------------------------
    @abc.abstractmethod
    def __int__(self) -> int: ...

    @abc.abstractmethod
    def is_zero(self) -> bool: ...


# ---------------------------------------------------------------------------
# Concrete implementation: F_p  with  p = 3 · 2^30 + 1
# ---------------------------------------------------------------------------

# Prime chosen so that the multiplicative group has a large 2-adic subgroup.
STARK_PRIME: int = 3 * (1 << 30) + 1  # 3221225473

# A generator of the full multiplicative group F_p^*  (order p - 1).
GENERATOR: int = 5  # 5 is a primitive root mod STARK_PRIME


class PrimeField:
    """
    Factory / namespace for a specific prime field.

    Usage::

        F = PrimeField(STARK_PRIME)
        a = F(7)
        b = F(11)
        c = a + b        # FieldElement(18)
        g = F.generator() # primitive root
    """

    def __init__(self, prime: int = STARK_PRIME, generator: int = GENERATOR) -> None:
        self.prime = prime
        self.generator_value = generator

    def __call__(self, value: int) -> "FieldElement":
        """Shortcut: ``F(v)`` creates a FieldElement."""
        return FieldElement(value, self.prime)

    def zero(self) -> "FieldElement":
        return FieldElement(0, self.prime)

    def one(self) -> "FieldElement":
        return FieldElement(1, self.prime)

    def generator(self) -> "FieldElement":
        """Return a primitive root of F_p^*."""
        return FieldElement(self.generator_value, self.prime)

    # ----- subgroup helpers (crucial for NTT / FFT over the field) ---------

    def get_subgroup_generator(self, order: int) -> "FieldElement":
        """
        Return an element whose multiplicative order is exactly *order*.

        *order* **must** divide p - 1.  We obtain it by raising the
        primitive root to the power  (p - 1) / order.
        """
        assert (self.prime - 1) % order == 0, (
            f"Requested order {order} does not divide p-1 = {self.prime - 1}"
        )
        exp = (self.prime - 1) // order
        return self.generator() ** exp

    def get_subgroup(self, order: int) -> list["FieldElement"]:
        """
        Return the unique multiplicative subgroup of the given *order*
        as a list  [g^0, g^1, …, g^{order-1}].
        """
        g = self.get_subgroup_generator(order)
        subgroup: list[FieldElement] = []
        current = self.one()
        for _ in range(order):
            subgroup.append(current)
            current = current * g
        return subgroup


# ---------------------------------------------------------------------------
# FieldElement — the workhorse class
# ---------------------------------------------------------------------------

class FieldElement(BaseField):
    """
    An element of the prime field F_p.

    All arithmetic is performed modulo *p*.  The internal ``value``
    is always stored in the canonical range [0, p).
    """

    __slots__ = ("value", "prime")

    def __init__(self, value: int, prime: int = STARK_PRIME) -> None:
        self.prime = prime
        self.value = value % prime

    # -- Construction helpers -----------------------------------------------

    @classmethod
    def zero(cls, prime: int = STARK_PRIME) -> "FieldElement":
        return cls(0, prime)

    @classmethod
    def one(cls, prime: int = STARK_PRIME) -> "FieldElement":
        return cls(1, prime)

    # -- Helpers to coerce ``other`` into a FieldElement --------------------

    def _coerce(self, other: Any) -> "FieldElement":
        if isinstance(other, FieldElement):
            assert self.prime == other.prime, "Field mismatch"
            return other
        if isinstance(other, int):
            return FieldElement(other, self.prime)
        return NotImplemented  # type: ignore[return-value]

    # -- Arithmetic (mod p) -------------------------------------------------

    def __add__(self, other: Any) -> "FieldElement":
        o = self._coerce(other)
        if o is NotImplemented:
            return NotImplemented  # type: ignore[return-value]
        return FieldElement((self.value + o.value) % self.prime, self.prime)

    def __radd__(self, other: Any) -> "FieldElement":
        return self.__add__(other)

    def __sub__(self, other: Any) -> "FieldElement":
        o = self._coerce(other)
        if o is NotImplemented:
            return NotImplemented  # type: ignore[return-value]
        return FieldElement((self.value - o.value) % self.prime, self.prime)

    def __rsub__(self, other: Any) -> "FieldElement":
        o = self._coerce(other)
        if o is NotImplemented:
            return NotImplemented  # type: ignore[return-value]
        return FieldElement((o.value - self.value) % self.prime, self.prime)

    def __mul__(self, other: Any) -> "FieldElement":
        o = self._coerce(other)
        if o is NotImplemented:
            return NotImplemented  # type: ignore[return-value]
        return FieldElement((self.value * o.value) % self.prime, self.prime)

    def __rmul__(self, other: Any) -> "FieldElement":
        return self.__mul__(other)

    def __truediv__(self, other: Any) -> "FieldElement":
        """Division is multiplication by the inverse: a / b = a · b^{-1}."""
        o = self._coerce(other)
        if o is NotImplemented:
            return NotImplemented  # type: ignore[return-value]
        return self * o.inverse()

    def __pow__(self, exp: int) -> "FieldElement":
        """
        Exponentiation via Python's built-in modular power
        (uses fast binary exponentiation internally).
        """
        # Handle negative exponents: a^{-n} = (a^{-1})^n
        if exp < 0:
            return self.inverse() ** (-exp)
        return FieldElement(pow(self.value, exp, self.prime), self.prime)

    def __neg__(self) -> "FieldElement":
        return FieldElement((-self.value) % self.prime, self.prime)

    def inverse(self) -> "FieldElement":
        """
        Multiplicative inverse via Fermat's little theorem:
            a^{-1} ≡ a^{p-2}  (mod p).
        Raises ValueError for the zero element.
        """
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert zero in a field.")
        return FieldElement(pow(self.value, self.prime - 2, self.prime), self.prime)

    # -- Comparison & hashing -----------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FieldElement):
            return self.value == other.value and self.prime == other.prime
        if isinstance(other, int):
            return self.value == other % self.prime
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.value, self.prime))

    def __bool__(self) -> bool:
        return self.value != 0

    # -- Representation -----------------------------------------------------

    def __repr__(self) -> str:
        return f"FieldElement({self.value})"

    def __str__(self) -> str:
        return str(self.value)

    def __int__(self) -> int:
        return self.value

    # -- Utilities ----------------------------------------------------------

    def is_zero(self) -> bool:
        return self.value == 0
