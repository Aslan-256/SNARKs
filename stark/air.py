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
        """Total number of rows in the trace (execution + padding).

        Must be a power of 2.  When zero-knowledge blinding is active this
        is strictly larger than :meth:`execution_trace_length`.
        """
        ...

    @abc.abstractmethod
    def execution_trace_length(self) -> int:
        """Number of rows that carry the *actual* computation.

        When zero-knowledge blinding is disabled this equals
        :meth:`trace_length`.  When blinding is active the remaining
        ``trace_length() - execution_trace_length()`` rows are filled
        with cryptographically random field elements that act as
        mathematical static, masking the trace polynomial from the
        verifier.
        """
        ...

    @abc.abstractmethod
    def num_registers(self) -> int:
        """Number of columns (registers) in the trace."""
        ...

    @abc.abstractmethod
    def generate_trace(self) -> List[List[FieldElement]]:
        """
        Produce the *execution* trace as a list of columns.
        ``trace[r][i]``  is the value of register *r* at step *i*.

        The returned columns have length :meth:`execution_trace_length`.
        The caller (typically the STARK prover) is responsible for
        appending the random blinding rows before interpolation.
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

    Zero-knowledge blinding
    -----------------------
    When ``num_randomizers > 0`` the AIR reserves additional *randomized
    padding rows* beyond the actual Fibonacci computation.  These rows
    are filled by the prover with cryptographically secure random field
    elements **before** polynomial interpolation.  Because the trace
    polynomial is uniquely determined by *all* evaluation points (execution
    **and** random padding), the extra degrees of freedom ensure that
    evaluations of the trace polynomial at arbitrary query points reveal no
    information about the secret witness.  Formally, for any fixed
    execution trace there are at least ``num_randomizers`` independent
    random coefficients in the resulting polynomial, so as long as
    ``num_randomizers > num_queries`` the verifier's queries are
    information-theoretically masked.

    The transition constraint and its zerofier are adjusted so that the
    polynomial constraints are only enforced on the execution rows,
    leaving the random rows unconstrained.

    *Note*:\n 
    In the next step of the pipeline, the STARK prover will take the 
    polynomials generated by ``transition_constraints`` and divide them by the 
    ``transition_zerofier`` to create the transition quotient polynomial. 
    It will then mix that with the boundary quotients to create the final 
    Composition Polynomial.

    Parameters
    ----------
    a0, a1 : int
        Starting values of the Fibonacci sequence.
    num_steps : int
        Number of actual Fibonacci computation steps.  **Must** be a power
        of 2 and at least 4.
    num_randomizers : int
        Number of random blinding rows appended after the execution trace
        for zero-knowledge.  When > 0 the total trace length is rounded up
        to the next power of 2 that accommodates ``num_steps +
        num_randomizers``.  Set to  ``num_queries + 1``  (or larger) to
        guarantee the zero-knowledge property.  Default is 0 (no blinding,
        fully backward-compatible).
    prime : int
        The prime modulus for the field.  Default is the STARK prime.
    """

    def __init__(
        self,
        a0: int = 1,
        a1: int = 1,
        num_steps: int = 8,  # must be power of 2
        num_randomizers: int = 0,
        prime: int = STARK_PRIME,
    ) -> None:
        assert num_steps & (num_steps - 1) == 0, "num_steps must be a power of 2"
        assert num_steps >= 4, "Need at least 4 steps for the Fibonacci AIR"
        assert num_randomizers >= 0, "num_randomizers must be non-negative"
        self.a0 = a0
        self.a1 = a1
        self._num_steps = num_steps
        self._num_randomizers = num_randomizers
        self.prime = prime
        self.field = PrimeField(prime)

        # Compute the padded trace length: the smallest power of 2 that
        # can hold the execution trace *plus* the randomized padding rows.
        # When num_randomizers == 0 the padded length equals num_steps and
        # the behaviour is identical to the original (unblinded) code.
        if num_randomizers > 0:
            total = num_steps + num_randomizers
            padded = 1
            while padded < total:
                padded <<= 1
            self._trace_length = padded
        else:
            self._trace_length = num_steps

    def trace_length(self) -> int:
        return self._trace_length

    def execution_trace_length(self) -> int:
        return self._num_steps

    @property
    def num_randomizers(self) -> int:
        """Number of random blinding rows requested."""
        return self._num_randomizers

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

        Instead of symbolically composing f(g·x) - which is expensive -
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
        Zerofier for the transition-constraint domain.

        The Fibonacci recurrence  a_{i+2} = a_{i+1} + a_i  applies at rows
        i = 0, 1, …, n_exec − 3  where  n_exec = execution_trace_length().
        The constraint references two steps ahead, so the last two
        *execution* rows (n_exec − 2 and n_exec − 1) are excluded.

        When zero-knowledge blinding is active (``num_randomizers > 0``)
        there are additional *padding* rows beyond the execution rows.
        These rows are filled with random field elements and must **not**
        be constrained, so they are also excluded from the zerofier.

        Concretely, let  n = trace_length()  (the full, possibly padded
        subgroup order) and  g  be its generator.  Then:

            Z_T(x)  =  (x^n − 1)  /  ∏_{i = n_exec − 2}^{n − 1} (x − g^i)

        which vanishes on {g^0, g^1, …, g^{n_exec − 3}} and *nowhere else*
        in the subgroup.  The excluded set has  n − n_exec + 2  elements.

        When there is no padding (n == n_exec) this reduces to the
        familiar  (x^n − 1) / ((x − g^{n−2})(x − g^{n−1})).
        """
        n = self.trace_length()
        n_exec = self.execution_trace_length()
        g = field.get_subgroup_generator(n)
        one = field.one()

        # Full subgroup zerofier  x^n - 1
        z_full = zerofier_on_subgroup(n, self.prime)

        # Exclusion polynomial:  ∏_{i = n_exec-2}^{n-1}  (x − g^i)
        # This removes the last two execution rows (where the recurrence
        # cannot be checked because it looks two steps ahead) as well as
        # *all* randomized padding rows that must stay unconstrained.
        exclusion = Polynomial([one])  # start with the constant 1
        for i in range(n_exec - 2, n):
            exclusion = exclusion * Polynomial([-(g ** i), one])

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

        Returns the list of quotient polynomials, one per boundary constraint.  
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
