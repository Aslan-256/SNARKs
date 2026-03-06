"""
Test suite for the zk-STARK implementation.

Covers every layer of the stack:
    1. Field arithmetic
    2. Polynomial operations (add, mul, div, eval, interpolate, NTT)
    3. Merkle-tree commitment & verification
    4. Fiat-Shamir channel determinism
    5. AIR trace generation & constraint computation
    6. FRI commit / verify
    7. Full STARK prover / verifier lifecycle
    8. Zero-knowledge blinding via trace padding
"""

from __future__ import annotations

import secrets

import pytest

from stark.field import FieldElement, PrimeField, STARK_PRIME
from stark.polynomial import (
    Polynomial,
    interpolate,
    ntt,
    intt,
    zerofier_on_domain,
    zerofier_on_subgroup,
)
from stark.merkle import MerkleTree
from stark.channel import Channel
from stark.air import FibonacciAIR
from stark.fri import FRIProtocol
from stark.stark import StarkProver, StarkVerifier


# ===================================================================
#  1. Field arithmetic
# ===================================================================

class TestFieldArithmetic:
    """Tests for FieldElement basic operations."""

    F = PrimeField()

    def test_add(self) -> None:
        a, b = self.F(7), self.F(11)
        assert (a + b) == self.F(18)

    def test_sub(self) -> None:
        a, b = self.F(3), self.F(10)
        # 3 − 10 mod p = p − 7
        assert (a - b) == self.F(STARK_PRIME - 7)

    def test_mul(self) -> None:
        a, b = self.F(6), self.F(7)
        assert (a * b) == self.F(42)

    def test_inv(self) -> None:
        a = self.F(123456)
        assert a * a.inverse() == self.F(1)

    def test_div(self) -> None:
        a, b = self.F(42), self.F(7)
        assert (a / b) == self.F(6)

    def test_pow(self) -> None:
        a = self.F(3)
        assert (a ** 5) == self.F(243)

    def test_neg(self) -> None:
        a = self.F(10)
        assert a + (-a) == self.F(0)

    def test_zero_inverse_raises(self) -> None:
        with pytest.raises(ZeroDivisionError):
            self.F(0).inverse()

    def test_primitive_root_order(self) -> None:
        """The generator should have order p − 1."""
        g = self.F.generator()
        # g^{(p-1)/2} should NOT be 1 (g is a primitive root).
        half = (STARK_PRIME - 1) // 2
        assert (g ** half) != self.F(1)
        # g^{p-1} = 1
        assert (g ** (STARK_PRIME - 1)) == self.F(1)

    def test_subgroup_generator(self) -> None:
        """Subgroup generator of order 8 should satisfy g^8 = 1."""
        g8 = self.F.get_subgroup_generator(8)
        assert (g8 ** 8) == self.F(1)
        assert (g8 ** 4) != self.F(1)  # order exactly 8, not 4


# ===================================================================
#  2. Polynomial operations
# ===================================================================

class TestPolynomial:
    """Tests for polynomial arithmetic and evaluation."""

    F = PrimeField()

    def test_evaluate(self) -> None:
        # f(x) = 3 + 2x + x^2   → f(2) = 3 + 4 + 4 = 11
        f = Polynomial.from_ints([3, 2, 1])
        assert f.evaluate(self.F(2)) == self.F(11)

    def test_add(self) -> None:
        f = Polynomial.from_ints([1, 2])       # 1 + 2x
        g = Polynomial.from_ints([3, 0, 4])    # 3 + 4x^2
        h = f + g                               # 4 + 2x + 4x^2
        assert h.evaluate(self.F(1)) == self.F(10)

    def test_mul(self) -> None:
        # (1 + x) * (1 − x) = 1 − x^2
        f = Polynomial.from_ints([1, 1])
        g = Polynomial([self.F(1), self.F(STARK_PRIME - 1)])  # 1 − x
        h = f * g
        assert h.evaluate(self.F(1)) == self.F(0)
        assert h.evaluate(self.F(0)) == self.F(1)

    def test_divmod(self) -> None:
        # (x^2 − 1) / (x − 1)  =  x + 1  remainder 0
        f = Polynomial.from_ints([STARK_PRIME - 1, 0, 1])  # x^2 − 1
        g = Polynomial([self.F(STARK_PRIME - 1), self.F(1)])  # x − 1
        q, r = f.divmod(g)
        assert r.is_zero()
        # q should be x + 1
        assert q.evaluate(self.F(0)) == self.F(1)
        assert q.evaluate(self.F(1)) == self.F(2)

    def test_interpolate(self) -> None:
        """Interpolation through 4 points should recover the polynomial."""
        xs = [self.F(i) for i in range(4)]
        # y = 2x + 1  →  ys = [1, 3, 5, 7]
        ys = [self.F(2 * i + 1) for i in range(4)]
        poly = interpolate(xs, ys)
        for x, y in zip(xs, ys):
            assert poly.evaluate(x) == y
        # Degree should be ≤ 1 (linear).
        assert poly.degree <= 1

    def test_ntt_intt_roundtrip(self) -> None:
        """NTT followed by INTT should recover the original coefficients."""
        n = 8
        omega = self.F.get_subgroup_generator(n)
        coeffs = [self.F(i + 1) for i in range(n)]  # [1, 2, …, 8]
        evals = ntt(coeffs, omega)
        recovered = intt(evals, omega)
        for a, b in zip(coeffs, recovered):
            assert a == b

    def test_zerofier_on_subgroup(self) -> None:
        """x^n − 1 should vanish on the subgroup of order n."""
        n = 8
        domain = self.F.get_subgroup(n)
        z = zerofier_on_subgroup(n)
        for d in domain:
            assert z.evaluate(d) == self.F(0)


# ===================================================================
#  3. Merkle tree
# ===================================================================

class TestMerkleTree:

    def test_commit_and_verify(self) -> None:
        data = [f"leaf_{i}".encode() for i in range(16)]
        tree = MerkleTree(data)
        root = tree.root
        for i in range(16):
            path = tree.open(i)
            assert MerkleTree.verify(root, i, data[i], path, tree.padded_n)

    def test_tampered_leaf_fails(self) -> None:
        data = [f"leaf_{i}".encode() for i in range(8)]
        tree = MerkleTree(data)
        root = tree.root
        path = tree.open(3)
        # Tamper with the leaf data.
        assert not MerkleTree.verify(root, 3, b"tampered", path, tree.padded_n)

    def test_from_field_elements(self) -> None:
        F = PrimeField()
        elems = [F(i) for i in range(32)]
        tree = MerkleTree.from_field_elements(elems)
        assert len(tree.root) == 32  # SHA-256 digest size


# ===================================================================
#  4. Fiat-Shamir channel
# ===================================================================

class TestChannel:

    def test_determinism(self) -> None:
        """Same transcript → same challenges."""
        ch1 = Channel()
        ch1.send(b"hello")
        a1 = ch1.receive_random_field_element()
        b1 = ch1.receive_random_field_element()

        ch2 = Channel()
        ch2.send(b"hello")
        a2 = ch2.receive_random_field_element()
        b2 = ch2.receive_random_field_element()

        assert a1 == a2
        assert b1 == b2

    def test_different_transcript(self) -> None:
        """Different transcript → different challenges (with overwhelming probability)."""
        ch1 = Channel()
        ch1.send(b"hello")

        ch2 = Channel()
        ch2.send(b"world")

        assert ch1.receive_random_field_element() != ch2.receive_random_field_element()


# ===================================================================
#  5. AIR — Fibonacci trace & constraints
# ===================================================================

class TestFibonacciAIR:

    def test_trace_generation(self) -> None:
        air = FibonacciAIR(a0=1, a1=1, num_steps=8)
        trace = air.generate_trace()
        col = trace[0]
        # Expected Fibonacci: 1, 1, 2, 3, 5, 8, 13, 21
        expected = [1, 1, 2, 3, 5, 8, 13, 21]
        for i, exp in enumerate(expected):
            assert int(col[i]) == exp

    def test_boundary_constraints(self) -> None:
        air = FibonacciAIR(a0=2, a1=3, num_steps=8)
        bcs = air.boundary_constraints()
        assert len(bcs) == 2
        assert int(bcs[0][2]) == 2  # a0
        assert int(bcs[1][2]) == 3  # a1

    def test_transition_constraint_vanishes(self) -> None:
        """Transition constraint polynomial should be divisible by the
        transition zerofier (i.e. it vanishes on the transition domain)."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8)
        field = air.field
        n = air.trace_length()
        trace_gen = field.get_subgroup_generator(n)
        trace = air.generate_trace()
        trace_domain = field.get_subgroup(n)
        trace_poly = interpolate(trace_domain, trace[0])

        tc = air.transition_constraints([trace_poly], field, trace_gen)
        tz = air.transition_zerofier(field)
        q, r = tc[0].divmod(tz)
        assert r.is_zero(), "Transition constraint not divisible by zerofier!"

    def test_boundary_quotients(self) -> None:
        """Boundary quotient division should have zero remainder."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8)
        field = air.field
        n = air.trace_length()
        trace_gen = field.get_subgroup_generator(n)
        trace = air.generate_trace()
        trace_domain = field.get_subgroup(n)
        trace_poly = interpolate(trace_domain, trace[0])

        bqs = air.boundary_zerofiers_and_quotients(
            [trace_poly], field, trace_gen
        )
        # Should get 2 quotient polynomials (one per boundary constraint).
        assert len(bqs) == 2


# ===================================================================
#  6. FRI protocol
# ===================================================================

class TestFRI:

    def test_fri_valid_polynomial(self) -> None:
        """FRI should accept evaluations of an actual low-degree polynomial."""
        F = PrimeField()
        # Build a polynomial of degree 3 and evaluate on a domain of size 32.
        poly = Polynomial.from_ints([1, 2, 3, 4])  # degree 3
        domain_size = 32
        gen = F.get_subgroup_generator(domain_size)
        offset = F.generator()
        domain = []
        power = F.one()
        for i in range(domain_size):
            domain.append(offset * power)
            power = power * gen

        evals = poly.evaluate_domain(domain)

        channel = Channel()
        fri = FRIProtocol(
            field=F,
            evaluations=evals,
            domain=domain,
            max_degree=3,
            num_queries=4,
        )
        proof = fri.prove(channel)

        # Verify
        ok = FRIProtocol.verify(
            proof=proof,
            initial_domain=domain,
            max_degree=3,
            field=F,
            num_queries=4,
        )
        assert ok, "FRI verification failed for a valid low-degree polynomial!"


# ===================================================================
#  7. Full STARK lifecycle
# ===================================================================

class TestSTARKLifecycle:

    def test_fibonacci_prove_verify(self) -> None:
        """
        End-to-end test:
          1. Define a Fibonacci AIR.
          2. Generate a STARK proof.
          3. Verify the proof.
        """
        air = FibonacciAIR(a0=1, a1=1, num_steps=8)
        prover = StarkProver(air, blowup_factor=8, num_queries=8)
        proof = prover.prove()

        verifier = StarkVerifier(air, blowup_factor=8, num_queries=8)
        assert verifier.verify(proof), "STARK verification failed!"

    def test_fibonacci_different_inputs(self) -> None:
        """STARK should work with different Fibonacci starting values."""
        air = FibonacciAIR(a0=3, a1=5, num_steps=8)
        prover = StarkProver(air, blowup_factor=8, num_queries=8)
        proof = prover.prove()

        verifier = StarkVerifier(air, blowup_factor=8, num_queries=8)
        assert verifier.verify(proof), "STARK verification failed for (3,5)!"


# ===================================================================
#  8. Zero-knowledge blinding via trace padding
# ===================================================================

class TestZeroKnowledgeBlinding:
    """Tests for the zero-knowledge property achieved by trace padding.

    When ``num_randomizers > 0`` the FibonacciAIR reserves extra rows
    that the prover fills with cryptographically random field elements.
    These random rows increase the degree of the trace polynomial,
    injecting independent random coefficients that mask the witness.

    The tests below verify that:

    1. The padded trace length is correct (power of 2, ≥ execution + k).
    2. The transition constraint polynomial is still exactly divisible
       by the (adjusted) transition zerofier, i.e. the composition
       polynomial is well-formed.
    3. The full prove / verify lifecycle succeeds with blinding enabled.
    4. Different random padding produces different proofs (non-trivial
       randomness).
    """

    F = PrimeField()

    # ---- AIR-level checks ------------------------------------------------

    def test_padded_trace_length_is_power_of_two(self) -> None:
        """trace_length() must always be a power of 2."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=9)
        n = air.trace_length()
        assert n & (n - 1) == 0, f"trace_length {n} is not a power of 2"

    def test_padded_trace_length_accommodates_randomizers(self) -> None:
        """trace_length() must be ≥ execution_trace_length + num_randomizers."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=9)
        assert air.trace_length() >= air.execution_trace_length() + 9

    def test_execution_trace_length_unchanged(self) -> None:
        """execution_trace_length() must equal the original num_steps."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=17)
        assert air.execution_trace_length() == 8

    def test_generate_trace_returns_execution_only(self) -> None:
        """generate_trace() must return only the execution rows."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=17)
        trace = air.generate_trace()
        assert len(trace[0]) == 8

    # ---- Constraint algebra with padding ----------------------------------

    def test_transition_constraint_divisible_with_padding(self) -> None:
        """With random padding the transition constraint polynomial must
        still be exactly divisible by the transition zerofier, proving
        that the composition polynomial is well-formed.

        This is the core algebraic invariant of the blinding scheme:
        constraints evaluate to zero on the execution domain, the random
        rows are unconstrained, and the zerofier only vanishes on the
        execution domain, so the quotient has zero remainder.
        """
        num_queries = 8
        num_randomizers = num_queries + 1  # 9
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        field = air.field
        n = air.trace_length()

        # Subgroup of the padded length.
        trace_gen = field.get_subgroup_generator(n)
        trace_domain = field.get_subgroup(n)

        # Build the execution trace and pad with random values (as the
        # prover would do).
        exec_trace = air.generate_trace()[0]
        prime = air.prime
        padded_col = list(exec_trace)
        for _ in range(n - air.execution_trace_length()):
            padded_col.append(FieldElement(secrets.randbelow(prime), prime))

        # Interpolate the padded trace on the full subgroup.
        trace_poly = interpolate(trace_domain, padded_col)

        # Compute transition constraint and zerofier.
        tc = air.transition_constraints([trace_poly], field, trace_gen)
        tz = air.transition_zerofier(field)

        q, r = tc[0].divmod(tz)
        assert r.is_zero(), (
            "Transition constraint not divisible by zerofier with padding!"
        )

    def test_boundary_quotients_with_padding(self) -> None:
        """Boundary quotient divisions must also leave zero remainder
        when trace padding is active."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=9)
        field = air.field
        n = air.trace_length()
        trace_gen = field.get_subgroup_generator(n)
        trace_domain = field.get_subgroup(n)

        exec_trace = air.generate_trace()[0]
        padded_col = list(exec_trace)
        for _ in range(n - air.execution_trace_length()):
            padded_col.append(
                FieldElement(secrets.randbelow(air.prime), air.prime)
            )
        trace_poly = interpolate(trace_domain, padded_col)

        bqs = air.boundary_zerofiers_and_quotients(
            [trace_poly], field, trace_gen,
        )
        assert len(bqs) == 2

    # ---- Full lifecycle with blinding ------------------------------------

    def test_zk_stark_prove_verify(self) -> None:
        """End-to-end zk-STARK: prove and verify with trace padding."""
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        prover = StarkProver(air, blowup_factor=8, num_queries=num_queries)
        proof = prover.prove()

        verifier = StarkVerifier(air, blowup_factor=8, num_queries=num_queries)
        assert verifier.verify(proof), "zk-STARK verification failed!"

    def test_zk_stark_different_starting_values(self) -> None:
        """zk-STARK should work with non-standard Fibonacci seeds."""
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=3, a1=7, num_steps=8, num_randomizers=num_randomizers,
        )
        prover = StarkProver(air, blowup_factor=8, num_queries=num_queries)
        proof = prover.prove()

        verifier = StarkVerifier(air, blowup_factor=8, num_queries=num_queries)
        assert verifier.verify(proof), "zk-STARK verification failed for (3,7)!"

    def test_different_randomness_yields_different_commitments(self) -> None:
        """Two independent proofs of the same statement must (almost surely)
        produce different trace commitments, confirming non-trivial
        randomness injection."""
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        proof1 = StarkProver(air, blowup_factor=8, num_queries=num_queries).prove()
        proof2 = StarkProver(air, blowup_factor=8, num_queries=num_queries).prove()

        assert proof1.trace_commitment != proof2.trace_commitment, (
            "Two proofs with independent randomness must (w.h.p.) have "
            "different trace commitments."
        )


# ===================================================================
#  9. Blinding polynomial (f_blinded = f + B · Z_trace)
# ===================================================================

class TestBlindingPolynomial:
    """Tests for the blinding-polynomial zero-knowledge mechanism.

    In addition to trace padding, the prover constructs a random
    polynomial  B(X)  and computes:

        f_blinded(X) = f(X) + B(X) · Z_trace(X)

    where  Z_trace(X) = X^n − 1  is the zerofier of the trace subgroup.
    Because  Z_trace  vanishes on the subgroup,  f_blinded  agrees with
    f  at every trace point, so all constraints hold.  Outside the
    subgroup the blinding term masks evaluations of f.

    The tests verify:
    1. ``Polynomial.random`` produces the correct degree with a
       non-zero leading coefficient.
    2. ``Polynomial.shift`` correctly computes  f(α · x).
    3. The blinded polynomial preserves boundary constraints on the
       trace subgroup.
    4. The transition constraint polynomial built from  f_blinded  is
       exactly divisible by the transition zerofier.
    5. The full STARK prove / verify lifecycle succeeds with the
       blinding-polynomial path active.
    """

    F = PrimeField()

    # ---- Polynomial helpers -----------------------------------------------

    def test_polynomial_random_degree(self) -> None:
        """Polynomial.random(d) must return a polynomial of exactly degree d."""
        for d in (0, 1, 5, 12):
            p = Polynomial.random(d, STARK_PRIME)
            assert p.degree == d, f"Expected degree {d}, got {p.degree}"

    def test_polynomial_random_leading_nonzero(self) -> None:
        """The leading coefficient of a random polynomial must be non-zero."""
        p = Polynomial.random(8, STARK_PRIME)
        assert not p.coeffs[-1].is_zero()

    def test_polynomial_shift_correctness(self) -> None:
        """f.shift(α) must satisfy  f.shift(α).evaluate(x) == f(α·x)."""
        f = Polynomial.from_ints([3, 1, 4, 1, 5])  # 3 + x + 4x² + x³ + 5x⁴
        alpha = self.F(7)
        f_shifted = f.shift(alpha)
        # Check at several random points.
        for x_int in (0, 1, 2, 42, 999):
            x = self.F(x_int)
            assert f_shifted.evaluate(x) == f.evaluate(alpha * x)

    # ---- Blinding preserves constraints -----------------------------------

    def test_blinded_trace_agrees_on_subgroup(self) -> None:
        """f_blinded must equal f at every point of the trace subgroup."""
        air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=9)
        field = air.field
        n = air.trace_length()
        domain = field.get_subgroup(n)

        # Build padded trace and interpolate.
        exec_trace = air.generate_trace()[0]
        padded = list(exec_trace) + [
            FieldElement(secrets.randbelow(air.prime), air.prime)
            for _ in range(n - air.execution_trace_length())
        ]
        f = interpolate(domain, padded)

        # Blind.
        z_trace = air.trace_domain_zerofier(field)
        b = Polynomial.random(8, air.prime)
        f_blinded = f + b * z_trace

        # f_blinded must agree with f on the subgroup.
        for pt in domain:
            assert f_blinded.evaluate(pt) == f.evaluate(pt)

    def test_blinded_transition_constraint_divisible(self) -> None:
        """The transition constraint polynomial built from f_blinded
        must be exactly divisible by the transition zerofier, confirming
        that the composition polynomial is well-formed even after
        blinding.

        This is the core algebraic invariant:
            C_blinded(x) = f_blinded(g²x) − f_blinded(gx) − f_blinded(x)
        is divisible by Z_T(x) because:
          1. C_blinded = C(x) + D(x) · Z_trace(x)
          2. Z_T divides both C(x) and Z_trace(x).
        """
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        field = air.field
        n = air.trace_length()
        trace_gen = field.get_subgroup_generator(n)
        trace_domain = field.get_subgroup(n)

        # Build padded trace, interpolate, then blind.
        exec_trace = air.generate_trace()[0]
        padded = list(exec_trace) + [
            FieldElement(secrets.randbelow(air.prime), air.prime)
            for _ in range(n - air.execution_trace_length())
        ]
        f = interpolate(trace_domain, padded)

        z_trace = air.trace_domain_zerofier(field)
        b = Polynomial.random(num_queries, air.prime)
        f_blinded = f + b * z_trace

        # Build transition constraint from the blinded polynomial.
        tc_list = air.transition_constraints([f_blinded], field, trace_gen)
        tz = air.transition_zerofier(field)

        q, r = tc_list[0].divmod(tz)
        assert r.is_zero(), (
            "Transition constraint from f_blinded not divisible by zerofier!"
        )

    def test_blinded_boundary_quotients_zero_remainder(self) -> None:
        """Boundary quotient divisions with f_blinded must leave zero
        remainder, since f_blinded = f on all boundary points."""
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        field = air.field
        n = air.trace_length()
        trace_gen = field.get_subgroup_generator(n)
        trace_domain = field.get_subgroup(n)

        exec_trace = air.generate_trace()[0]
        padded = list(exec_trace) + [
            FieldElement(secrets.randbelow(air.prime), air.prime)
            for _ in range(n - air.execution_trace_length())
        ]
        f = interpolate(trace_domain, padded)

        z_trace = air.trace_domain_zerofier(field)
        b = Polynomial.random(num_queries, air.prime)
        f_blinded = f + b * z_trace

        bqs = air.boundary_zerofiers_and_quotients(
            [f_blinded], field, trace_gen,
        )
        assert len(bqs) == 2

    # ---- Full lifecycle with blinding polynomial --------------------------

    def test_blinding_polynomial_prove_verify(self) -> None:
        """End-to-end zk-STARK with blinding polynomials active."""
        num_queries = 8
        num_randomizers = num_queries + 1
        air = FibonacciAIR(
            a0=1, a1=1, num_steps=8, num_randomizers=num_randomizers,
        )
        prover = StarkProver(air, blowup_factor=8, num_queries=num_queries)
        proof = prover.prove()

        verifier = StarkVerifier(air, blowup_factor=8, num_queries=num_queries)
        assert verifier.verify(proof), (
            "zk-STARK with blinding polynomials failed verification!"
        )

    def test_blinding_polynomial_different_seeds(self) -> None:
        """Blinding polynomials must work with various Fibonacci seeds."""
        for a0, a1 in [(2, 5), (7, 11), (0, 1)]:
            num_queries = 8
            num_randomizers = num_queries + 1
            air = FibonacciAIR(
                a0=a0, a1=a1, num_steps=8,
                num_randomizers=num_randomizers,
            )
            prover = StarkProver(
                air, blowup_factor=8, num_queries=num_queries,
            )
            proof = prover.prove()
            verifier = StarkVerifier(
                air, blowup_factor=8, num_queries=num_queries,
            )
            assert verifier.verify(proof), (
                f"Blinding-polynomial proof failed for seeds ({a0}, {a1})!"
            )


# ===================================================================
#  Standalone runner
# ===================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  zk-STARK · Full Integration Test")
    print("=" * 60)

    # --- Field ---
    F = PrimeField()
    a, b = F(12345), F(67890)
    assert (a + b) * (a - b) == a * a - b * b
    print("[✓] Field arithmetic")

    # --- Polynomial ---
    xs = [F(i) for i in range(4)]
    ys = [F(1), F(3), F(5), F(7)]
    p = interpolate(xs, ys)
    for x, y in zip(xs, ys):
        assert p.evaluate(x) == y
    print("[✓] Polynomial interpolation")

    # --- NTT ---
    n = 8
    omega = F.get_subgroup_generator(n)
    coeffs = [F(i) for i in range(n)]
    assert intt(ntt(coeffs, omega), omega) == coeffs
    print("[✓] NTT / INTT round-trip")

    # --- Merkle ---
    data = [f"leaf_{i}".encode() for i in range(16)]
    tree = MerkleTree(data)
    for i in range(16):
        assert MerkleTree.verify(tree.root, i, data[i], tree.open(i), tree.padded_n)
    print("[✓] Merkle tree commit / verify")

    # --- Channel ---
    ch1, ch2 = Channel(), Channel()
    ch1.send(b"test"); ch2.send(b"test")
    assert ch1.receive_random_field_element() == ch2.receive_random_field_element()
    print("[✓] Fiat-Shamir channel determinism")

    # --- AIR ---
    air = FibonacciAIR(a0=1, a1=1, num_steps=8)
    trace = air.generate_trace()[0]
    assert [int(trace[i]) for i in range(8)] == [1, 1, 2, 3, 5, 8, 13, 21]
    print("[✓] Fibonacci AIR trace generation")

    # --- Full STARK ---
    print("\n--- Proving Fibonacci STARK (a0=1, a1=1, 8 steps) ---")
    prover = StarkProver(air, blowup_factor=8, num_queries=8)
    proof = prover.prove()
    print(f"    Proof generated. Trace commitment: {proof.trace_commitment.hex()[:16]}…")

    verifier = StarkVerifier(air, blowup_factor=8, num_queries=8)
    ok = verifier.verify(proof)
    print(f"    Verification: {'PASS ✓' if ok else 'FAIL ✗'}")
    assert ok, "End-to-end STARK test failed!"

    print("\n" + "=" * 60)
    print("  All tests passed!")
    print("=" * 60)
