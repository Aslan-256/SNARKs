"""
snarks.air - Algebraic Intermediate Representation (AIR).

Mathematical background
-----------------------
An **AIR** (Algebraic Intermediate Representation) describes a computation as
a set of polynomial constraints over an **execution trace**.

Execution trace
    A matrix  T  of field elements with  *w* columns ("registers") and  *n*
    rows ("steps").  Each row represents the state of the computation at one
    point in time.

Transition constraints
    Polynomial relations that must hold between consecutive rows.  For a
    Fibonacci-like computation with one register the constraint is:
        T(i+2) = T(i+1) + T(i)     for i = 0, …, n-3
    or equivalently  T(i+2) - T(i+1) - T(i) = 0.

Boundary constraints
    Values that specific registers must hold at specific rows.
    E.g.  T(0) = a_0,  T(1) = a_1.

In the STARK pipeline the prover interpolates each trace column as a
polynomial over a subgroup, then shows that the constraint polynomial
is divisible by the "zerofier" of the relevant domain.

AIR is crucial for modern zero-knowledge virtual machines (zkVMs) and 
verifiable ML, where it helps prove that a computational graph or program 
was executed correctly. 

This module provides an abstract base class ``AIR`` and a concrete
``FibonacciAIR`` that constrains a single-register Fibonacci sequence.
"""

from __future__ import annotations

import abc
from typing import Dict, List, Tuple

from stark.field import FieldElement, PrimeField, STARK_PRIME
from stark.polynomial import Polynomial, interpolate, zerofier_on_subgroup


class AIR(abc.ABC):
    """Abstract base class for an AIR instance."""

    @abc.abstractmethod
    def trace_length(self) -> int:
        """Number of rows in the execution trace (must be a power of 2)."""
        ...

    @abc.abstractmethod
    def num_registers(self) -> int:
        """Number of columns (registers) in the trace."""
        ...

    @abc.abstractmethod
    def generate_trace(self) -> List[List[FieldElement]]:
        """
        Produce the full execution trace as a list of columns.
        ``trace[r][i]``  is the value of register *r* at step *i*.
        """
        ...

    @abc.abstractmethod
    def boundary_constraints(self) -> List[Tuple[int, int, FieldElement]]:
        """
        Return a list of (register, step, value) triples that pin
        specific cells of the trace.
        """
        ...

    @abc.abstractmethod
    def transition_constraints(
        self,
        trace_polys: List[Polynomial],
        field: PrimeField,
        subgroup_gen: FieldElement,
    ) -> List[Polynomial]:
        """
        Build the *transition constraint polynomials*.

        Each returned polynomial must vanish on the "transition domain"
        (the subgroup minus the last rows where the constraint does not
        apply).
        """
        ...

    @abc.abstractmethod
    def transition_zerofier(self, field: PrimeField) -> Polynomial:
        """
        The polynomial that vanishes on every row where the transition
        constraint must hold.
        """
        ...

    @abc.abstractmethod
    def boundary_zerofiers_and_quotients(
        self,
        trace_polys: List[Polynomial],
        field: PrimeField,
        subgroup_gen: FieldElement,
    ) -> List[Polynomial]:
        """
        For each boundary constraint, compute:
            ( trace_poly(x) - value ) / ( x - omega^step )
        and return them as polynomials.
        """
        ...


# ---------------------------------------------------------------------------
#  Concrete: Fibonacci AIR (single register)
# ---------------------------------------------------------------------------

class FibonacciAIR(AIR):
    """
    AIR for the recurrence  a_{i+2} = a_{i+1} + a_{i}.

    The trace has **one register** and ``n`` rows.  The boundary constraints
    pin the first two values (a_0, a_1).  The transition constraint is:

        f(g^{i+2} · x) - f(g^{i+1} · x) - f(g^i · x) = 0

    which, when evaluated on the trace subgroup, encodes the Fibonacci rule.

    Parameters
    ----------
    a0, a1 : int
        Starting values of the Fibonacci sequence.
    num_steps : int
        Length of the trace.  **Must** be a power of 2 (as the prover will 
        interpolate polynomials over a subgroup of this size).
    prime : int
        The prime modulus for the field.  Default is the STARK prime.
    """

    def __init__(
        self,
        a0: int = 1,
        a1: int = 1,
        num_steps: int = 8,  # must be power of 2
        prime: int = STARK_PRIME,
    ) -> None:
        assert num_steps & (num_steps - 1) == 0, "num_steps must be a power of 2"
        assert num_steps >= 4, "Need at least 4 steps for the Fibonacci AIR"
        self.a0 = a0
        self.a1 = a1
        self._num_steps = num_steps
        self.prime = prime
        self.field = PrimeField(prime)

    def trace_length(self) -> int:
        return self._num_steps

    def num_registers(self) -> int:
        return 1  # single-column trace

    def generate_trace(self) -> List[List[FieldElement]]:
        """
        Compute the Fibonacci trace:
            a_0, a_1, a_0+a_1, a_1+(a_0+a_1), …
        Return as ``[column_0]`` where ``column_0[i]`` is a_i.
        """
        F = self.field
        n = self._num_steps
        col: List[FieldElement] = [F(0)] * n
        col[0] = F(self.a0)
        col[1] = F(self.a1)
        for i in range(2, n):
            col[i] = col[i - 1] + col[i - 2]
        return [col]

    def boundary_constraints(self) -> List[Tuple[int, int, FieldElement]]:
        """
        Pin f(omega^0) = a_0  and  f(omega^1) = a_1.
        Each tuple is  (register_index, row_index, expected_value).
        """
        F = self.field
        return [
            (0, 0, F(self.a0)),
            (0, 1, F(self.a1)),
        ]

    def transition_constraints(
        self,
        trace_polys: List[Polynomial],
        field: PrimeField,
        subgroup_gen: FieldElement,
    ) -> List[Polynomial]:
        """
        Build the transition constraint polynomial:
            C(x) = f(g² · x) - f(g · x) - f(x)

        where f is the trace polynomial interpolated over the subgroup
        {1, g, g², …, g^{n-1}} and g = subgroup_gen.

        C(x) should vanish for x = g^i  with i = 0, …, n-3.

        Instead of symbolically composing f(g·x) — which is expensive —
        we evaluate f on the shifted domain directly and interpolate.
        """
        f = trace_polys[0]
        n = self.trace_length()

        # Get subgroup elements: omega^0, omega^1, …, omega^{n-1}
        g = subgroup_gen
        domain = field.get_subgroup(n)

        # Evaluate f on the subgroup (these are just the trace values).
        f_vals = f.evaluate_domain(domain)

        # Build C(x) evaluations:  C(omega^i) = f_{i+2} - f_{i+1} - f_i
        # for i in [0, n-1].  Indices wrap around modulo n (the polynomial
        # identity is valid everywhere but we will divide out the zerofier).
        c_vals: List[FieldElement] = []
        for i in range(n):
            c_vals.append(
                f_vals[(i + 2) % n] - f_vals[(i + 1) % n] - f_vals[i]
            )

        # Interpolate C(x) from its evaluations on the subgroup.
        c_poly = interpolate(domain, c_vals)
        return [c_poly]

    def transition_zerofier(self, field: PrimeField) -> Polynomial:
        """
        The transition constraint must hold at rows 0 through n-3.
        The zerofier is:
            Z_T(x) = (x^n - 1) / ((x - g^{n-2}) · (x - g^{n-1}))

        i.e. it vanishes on {g^0, …, g^{n-3}} but NOT on the last two rows.
        We compute this by polynomial division.
        """
        n = self.trace_length()
        g = field.get_subgroup_generator(n)
        one = field.one()

        # Full subgroup zerofier  x^n - 1
        z_full = zerofier_on_subgroup(n, self.prime)

        # Exclude the last two points:  (x - g^{n-2})(x - g^{n-1})
        gn2 = g ** (n - 2)
        gn1 = g ** (n - 1)
        exclusion = Polynomial([-gn2, one]) * Polynomial([-gn1, one])

        z_transition, remainder = z_full.divmod(exclusion)
        # Sanity: remainder should be zero
        assert remainder.is_zero(), "Transition zerofier division has non-zero remainder!"
        return z_transition

    def boundary_zerofiers_and_quotients(
        self,
        trace_polys: List[Polynomial],
        field: PrimeField,
        subgroup_gen: FieldElement,
    ) -> List[Polynomial]:
        """
        For each boundary constraint  (reg, step, val):
            quotient_i(x) = (f_{reg}(x) - val) / (x - omega^{step})

        Returns the list of quotient polynomials.
        """
        one = field.one()
        quotients: List[Polynomial] = []
        for reg, step, val in self.boundary_constraints():
            f = trace_polys[reg]
            # Numerator:  f(x) - val
            numerator = f - Polynomial([val])
            # Denominator:  x - omega^{step}
            point = subgroup_gen ** step
            denominator = Polynomial([-point, one])
            q, r = numerator.divmod(denominator)
            assert r.is_zero(), (
                f"Boundary constraint (reg={reg}, step={step}) not satisfied!"
            )
            quotients.append(q)
        return quotients
