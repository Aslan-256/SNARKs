"""
snarks.polynomial - Polynomial arithmetic, interpolation, and FFT/NTT.

Mathematical background
-----------------------
Polynomials over a finite field F_p are the backbone of STARK arithmetization.

Key operations:
* **Evaluation / Multi-point evaluation** - compute f(x) for many x values.
* **Interpolation** - given (x_i, y_i) pairs, recover the unique polynomial of
  degree < n passing through all of them.
* **Low-Degree Extension (LDE)** - evaluate a low-degree polynomial on a much
  larger domain.  This is what the prover commits to; the "blowup" makes the
  Reed-Solomon code have high minimum distance, which is essential for
  soundness.
* **Number Theoretic Transform (NTT)** - the finite-field analogue of the
  FFT.  Over F_p whose multiplicative group has a subgroup of order 2^k, we
  can evaluate / interpolate a polynomial on such a subgroup in O(n log n)
  field operations.

Implementation notes
--------------------
Polynomials are stored in **coefficient form**: ``coeffs[i]`` is the
coefficient of x^i.  Trailing zeros are stripped to keep the degree canonical.
"""

from __future__ import annotations

import secrets
from typing import List, Optional, Sequence

from stark.field import FieldElement, PrimeField, STARK_PRIME


# ---------------------------------------------------------------------------
# Polynomial class
# ---------------------------------------------------------------------------

class Polynomial:
    """
    Univariate polynomial over a prime field.

    ``coeffs[i]`` is the coefficient of x^i.  The list is stored with
    trailing zeros removed so that ``len(coeffs) - 1 == degree`` (with the
    convention that the zero polynomial has degree -1).
    """

    def __init__(self, coeffs: List[FieldElement]) -> None:
        # Strip trailing zeros for a canonical representation.
        self.coeffs = list(coeffs)
        self._strip()

    # ----- helpers ---------------------------------------------------------

    def _strip(self) -> None:
        """Remove trailing zero coefficients."""
        while self.coeffs and self.coeffs[-1].is_zero():
            self.coeffs.pop()

    @property
    def degree(self) -> int:
        """Degree of the polynomial (-1 for the zero polynomial)."""
        return len(self.coeffs) - 1

    @property
    def prime(self) -> int:
        if self.coeffs:
            return self.coeffs[0].prime
        return STARK_PRIME

    def is_zero(self) -> bool:
        return len(self.coeffs) == 0

    # ----- construction helpers --------------------------------------------

    @classmethod
    def zero(cls, _: int = STARK_PRIME) -> "Polynomial":
        return cls([])

    @classmethod
    def constant(cls, c: FieldElement) -> "Polynomial":
        return cls([c])

    @classmethod
    def monomial(cls, degree: int, coeff: FieldElement) -> "Polynomial":
        """Return ``coeff * x^degree``."""
        prime = coeff.prime
        zeros = [FieldElement(0, prime)] * degree
        return cls(zeros + [coeff])

    @classmethod
    def from_ints(cls, values: Sequence[int], prime: int = STARK_PRIME) -> "Polynomial":
        """Convenience: build a polynomial from plain integers."""
        return cls([FieldElement(v, prime) for v in values])

    @classmethod
    def random(cls, degree: int, prime: int = STARK_PRIME) -> "Polynomial":
        """
        Generate a polynomial of the given *degree* whose coefficients are
        drawn independently and uniformly from F_p using a
        **cryptographically secure** random number generator
        (``secrets.randbelow``).

        This is used in the STARK prover to construct **blinding
        polynomials** that mask the trace polynomial, providing the
        zero-knowledge property.  A blinding polynomial B(X) of degree
        *d* contributes *d + 1* independent random field elements; when
        *d ≥ num_queries* the resulting mask acts as a one-time pad over
        the verifier's spot-check queries.

        Parameters
        ----------
        degree : int
            The exact degree of the returned polynomial.  The leading
            coefficient is guaranteed to be non-zero.
        prime : int
            The prime modulus of the underlying field.

        Returns
        -------
        Polynomial
            A random polynomial of the specified degree.
        """
        assert degree >= 0, "degree must be non-negative"
        coeffs = [
            FieldElement(secrets.randbelow(prime), prime)
            for _ in range(degree + 1)
        ]
        # Ensure the leading coefficient is non-zero so that the
        # degree is exactly as requested.
        while coeffs[-1].is_zero():
            coeffs[-1] = FieldElement(secrets.randbelow(prime), prime)
        return cls(coeffs)

    # ----- evaluation ------------------------------------------------------

    def evaluate(self, x: FieldElement) -> FieldElement:
        """
        Evaluate the polynomial at a single point using **Horner's method**:
            f(x) = c_0 + x (c_1 + x (c_2 + … ))
        which is O(degree) multiplications.
        """
        if not self.coeffs:
            return FieldElement(0, x.prime)
        result = FieldElement(0, x.prime)
        for c in reversed(self.coeffs):
            result = result * x + c
        return result

    def evaluate_domain(self, domain: List[FieldElement]) -> List[FieldElement]:
        """Evaluate the polynomial at every point in *domain*."""
        return [self.evaluate(x) for x in domain]

    # ----- arithmetic ------------------------------------------------------

    def __add__(self, other: "Polynomial") -> "Polynomial":
        n = max(len(self.coeffs), len(other.coeffs))
        prime = self.prime
        result = []
        for i in range(n):
            a = self.coeffs[i] if i < len(self.coeffs) else FieldElement(0, prime)
            b = other.coeffs[i] if i < len(other.coeffs) else FieldElement(0, prime)
            result.append(a + b)
        return Polynomial(result)

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        n = max(len(self.coeffs), len(other.coeffs))
        prime = self.prime
        result = []
        for i in range(n):
            a = self.coeffs[i] if i < len(self.coeffs) else FieldElement(0, prime)
            b = other.coeffs[i] if i < len(other.coeffs) else FieldElement(0, prime)
            result.append(a - b)
        return Polynomial(result)

    def __neg__(self) -> "Polynomial":
        return Polynomial([-c for c in self.coeffs])

    def __mul__(self, other: "Polynomial | FieldElement | int") -> "Polynomial":
        """
        Polynomial × polynomial  (schoolbook O(n²)  - fine for the sizes
        we deal with in this pedagogical implementation).
        Scalar × polynomial is handled as a special case.
        """
        if isinstance(other, (FieldElement, int)):
            if isinstance(other, int):
                other = FieldElement(other, self.prime)
            return Polynomial([c * other for c in self.coeffs])

        if self.is_zero() or other.is_zero():
            return Polynomial.zero(self.prime)

        prime = self.prime
        n = len(self.coeffs) + len(other.coeffs) - 1
        result = [FieldElement(0, prime) for _ in range(n)]
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                result[i + j] = result[i + j] + a * b
        return Polynomial(result)

    def __rmul__(self, other: "FieldElement | int") -> "Polynomial":
        return self.__mul__(other)

    def scalar_mul(self, scalar: FieldElement) -> "Polynomial":
        return Polynomial([c * scalar for c in self.coeffs])

    # ----- modular arithmetic for polynomials ------------------------------

    def __mod__(self, other: "Polynomial") -> "Polynomial":
        """Polynomial remainder  self mod other."""
        _, r = self.divmod(other)
        return r

    def __floordiv__(self, other: "Polynomial") -> "Polynomial":
        """Polynomial quotient  self // other."""
        q, _ = self.divmod(other)
        return q

    def divmod(self, divisor: "Polynomial") -> tuple["Polynomial", "Polynomial"]:
        """
        Polynomial long division.  Returns (quotient, remainder) such that
            self = quotient * divisor + remainder
        with deg(remainder) < deg(divisor).
        """
        if divisor.is_zero():
            raise ZeroDivisionError("Division by zero polynomial.")
        prime = self.prime
        remainder = list(self.coeffs)  # work on a copy
        deg_d = divisor.degree
        lead_inv = divisor.coeffs[-1].inverse()
        quotient = [FieldElement(0, prime)] * (len(remainder) - deg_d)

        for i in range(len(remainder) - 1, deg_d - 1, -1):
            if remainder[i].is_zero():
                continue
            coeff = remainder[i] * lead_inv
            quotient[i - deg_d] = coeff
            for j in range(deg_d + 1):
                remainder[i - deg_d + j] = (
                    remainder[i - deg_d + j] - coeff * divisor.coeffs[j]
                )
        return Polynomial(quotient), Polynomial(remainder)

    # ----- composition / shifting ------------------------------------------

    def shift(self, alpha: FieldElement) -> "Polynomial":
        """
        Return the polynomial  f(alpha · x)  obtained by substituting  alpha·x
        for  x.

        If  f(x) = Σ_i c_i x^i  then  f(alpha·x) = Σ_i (c_i · alpha^i) x^i.

        This is an O(degree) operation that avoids the expense of full
        polynomial composition.  It is used to compute shifted trace
        polynomials  f(g·x)  and  f(g²·x)  when building transition
        constraints in coefficient form.
        """
        if not self.coeffs:
            return Polynomial([])
        result: List[FieldElement] = []
        alpha_power = FieldElement(1, alpha.prime)  # α^0 = 1
        for c in self.coeffs:
            result.append(c * alpha_power)
            alpha_power = alpha_power * alpha
        return Polynomial(result)

    def compose(self, inner: "Polynomial") -> "Polynomial":
        """
        Compose self(inner(x))  - used when folding in FRI.
        Implemented via Horner-like approach in polynomial space.
        """
        if not self.coeffs:
            return Polynomial.zero(self.prime)
        result = Polynomial.constant(self.coeffs[-1])
        for c in reversed(self.coeffs[:-1]):
            result = result * inner + Polynomial.constant(c)
        return result

    # ----- representation --------------------------------------------------

    def __repr__(self) -> str:
        terms = []
        for i, c in enumerate(self.coeffs):
            if c.is_zero():
                continue
            if i == 0:
                terms.append(str(c))
            elif i == 1:
                terms.append(f"{c}·x")
            else:
                terms.append(f"{c}·x^{i}")
        return " + ".join(terms) if terms else "0"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self.coeffs == other.coeffs

    def __len__(self) -> int:
        return len(self.coeffs)


# ---------------------------------------------------------------------------
#  Lagrange interpolation (O(n²) - simple and correct)
# ---------------------------------------------------------------------------

def interpolate(
    xs: List[FieldElement], ys: List[FieldElement]
) -> Polynomial:
    """
    Given n points (x_i, y_i), return the unique polynomial of degree < n
    passing through all of them via **Lagrange interpolation**.

    Complexity: O(n²) field operations.

    Formula:
        L(x) = Σ_i  y_i · Π_{j≠i} (x − x_j) / (x_i − x_j)
    """
    assert len(xs) == len(ys), "xs and ys must have the same length."
    n = len(xs)
    prime = xs[0].prime
    zero = FieldElement(0, prime)
    one = FieldElement(1, prime)

    # Accumulator for the resulting polynomial
    result = Polynomial([])

    for i in range(n):
        # Build the i-th Lagrange basis polynomial  l_i(x)
        # l_i(x) = Π_{j ≠ i}  (x − x_j) / (x_i − x_j)
        numerator = Polynomial([one])  # start with "1"
        denominator = one

        for j in range(n):
            if j == i:
                continue
            # numerator *= (x − x_j)
            numerator = numerator * Polynomial([-xs[j], one])
            # denominator *= (x_i − x_j)
            denominator = denominator * (xs[i] - xs[j])

        # Scale: l_i(x) = numerator / denominator,  then multiply by y_i
        basis = numerator.scalar_mul(ys[i] * denominator.inverse())
        result = result + basis

    return result


# ---------------------------------------------------------------------------
#  NTT (Number Theoretic Transform) - O(n log n) evaluation & interpolation
# ---------------------------------------------------------------------------

def ntt(
    coeffs: List[FieldElement],
    omega: FieldElement,
) -> List[FieldElement]:
    """
    Evaluate the polynomial (given in coefficient form) on the coset
        {omega^0, omega^1, …, omega^{n-1}}
    using a radix-2 Cooley-Tukey NTT.

    **Preconditions**:
    * ``len(coeffs)`` must be a power of 2.
    * ``omega`` must be a primitive n-th root of unity in the field.

    This is the finite-field analogue of the FFT and runs in O(n log n).
    """
    n = len(coeffs)
    if n == 1:
        return list(coeffs)

    assert n & (n - 1) == 0, "Length must be a power of 2."

    # Split into even and odd indexed coefficients  (Cooley-Tukey butterfly)
    even = ntt(coeffs[0::2], omega * omega)
    odd = ntt(coeffs[1::2], omega * omega)

    # Combine
    result = [FieldElement(0, omega.prime)] * n
    w = FieldElement(1, omega.prime)  # omega^0

    half = n // 2
    for k in range(half):
        t = w * odd[k]
        result[k] = even[k] + t
        result[k + half] = even[k] - t
        w = w * omega

    return result


def intt(
    values: List[FieldElement],
    omega: FieldElement,
) -> List[FieldElement]:
    """
    Inverse NTT: convert evaluations back to coefficient form.

    Uses the fact that INTT is just NTT with omega^{-1}, followed by
    dividing each coefficient by n.
    """
    n = len(values)
    omega_inv = omega.inverse()
    coeffs = ntt(values, omega_inv)
    n_inv = FieldElement(n, omega.prime).inverse()
    return [c * n_inv for c in coeffs]


# ---------------------------------------------------------------------------
#  Helper: "zerofier" polynomial that vanishes on a given domain
# ---------------------------------------------------------------------------

def zerofier_on_domain(domain: List[FieldElement]) -> Polynomial:
    """
    Build  Z(x) = Π_{d ∈ domain} (x − d).

    This polynomial is zero on every point of *domain*.  It is used
    extensively in STARK constraint composition: if a constraint C(x)
    must vanish on the trace domain D, we check that  C(x) / Z_D(x) is
    a polynomial (i.e. the division has zero remainder).
    """
    prime = domain[0].prime
    one = FieldElement(1, prime)
    result = Polynomial([one])
    for d in domain:
        result = result * Polynomial([-d, one])
    return result


def zerofier_on_subgroup(order: int, prime: int = STARK_PRIME) -> Polynomial:
    """
    For a multiplicative subgroup of the given *order*, the zerofier is
    simply  x^{order} − 1   (because every element g of the subgroup
    satisfies  g^{order} = 1).

    This compact form is **much** more efficient to work with than
    expanding the product of (x − g^i) for every i.
    """
    coeffs = [FieldElement(0, prime)] * (order + 1)
    coeffs[0] = FieldElement(-1, prime)   # constant term: −1
    coeffs[order] = FieldElement(1, prime)  # leading term: x^{order}
    return Polynomial(coeffs)
