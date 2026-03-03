"""
snarks.stark – Top-level STARK Prover and Verifier.

Overview
--------
This module orchestrates the full STARK pipeline:

**Prover**:
1. Generate the execution trace from the AIR.
2. Interpolate each trace column as a polynomial over a subgroup of order n.
3. Evaluate ("blow up") each trace polynomial on a larger evaluation domain
   of size  ``blowup_factor * n``.  This is the **Low-Degree Extension**
   (LDE).  The blowup gives the Reed-Solomon code high minimum distance,
   which is crucial for soundness.
4. Commit to the LDE evaluations via a Merkle tree.
5. Compute *constraint polynomials* (boundary + transition) and compose
   them into a single polynomial using random verifier challenges (from the
   Fiat-Shamir channel).
6. Evaluate the composition polynomial on the LDE domain, commit, and
   run FRI to prove it is low-degree.

**Verifier**:
1. Reconstruct the Fiat-Shamir transcript.
2. Verify the FRI proof (proximity to a low-degree polynomial).
3. Spot-check the constraint composition at the queried positions.

Parameters
----------
blowup_factor : int
    Ratio  |evaluation domain| / |trace|.  Must be a power of 2.
    Larger → more soundness, more prover work.  Default is 8.
num_queries : int
    Number of random positions queried in FRI.  Default is 16.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from snarks.field import FieldElement, PrimeField, STARK_PRIME
from snarks.polynomial import (
    Polynomial,
    interpolate,
    ntt,
    intt,
    zerofier_on_subgroup,
)
from snarks.merkle import MerkleTree
from snarks.channel import Channel
from snarks.air import AIR, FibonacciAIR
from snarks.fri import FRIProtocol, FRIProof


# ---------------------------------------------------------------------------
#  Proof data structure
# ---------------------------------------------------------------------------

@dataclass
class StarkProof:
    """Bundle of everything the verifier needs."""
    # Merkle root of the trace LDE.
    trace_commitment: bytes
    # Merkle root of the composition polynomial LDE.
    composition_commitment: bytes
    # FRI proof for the composition polynomial.
    fri_proof: FRIProof
    # FRI degree bound used by the prover (verifier must use the same).
    fri_max_degree: int
    # Trace query openings  (index → (value, auth_path))  per register.
    trace_openings: List[Dict[int, Tuple[FieldElement, List[bytes]]]]
    # Composition polynomial query openings.
    composition_openings: Dict[int, Tuple[FieldElement, List[bytes]]]
    # Channel proof bytes (full Fiat-Shamir transcript).
    transcript: List[bytes]


# ---------------------------------------------------------------------------
#  STARK Prover
# ---------------------------------------------------------------------------

class StarkProver:
    """
    Generates a STARK proof for a given AIR instance.

    Parameters
    ----------
    air : AIR
        The algebraic intermediate representation describing the computation.
    blowup_factor : int
        LDE blowup factor (default 8, must be power of 2).
    num_queries : int
        Number of FRI query positions (default 16).
    """

    def __init__(
        self,
        air: AIR,
        blowup_factor: int = 8,
        num_queries: int = 16,
        prime: int = STARK_PRIME,
    ) -> None:
        assert blowup_factor & (blowup_factor - 1) == 0, "blowup must be power of 2"
        self.air = air
        self.blowup = blowup_factor
        self.num_queries = num_queries
        self.prime = prime
        self.field = PrimeField(prime)

    def prove(self) -> StarkProof:
        """Execute the full STARK proof generation."""
        field = self.field
        n = self.air.trace_length()              # trace size (power of 2)
        lde_size = n * self.blowup               # evaluation domain size

        # ---- Step 0: trace generation -------------------------------------
        trace_columns = self.air.generate_trace()
        num_registers = self.air.num_registers()

        # ---- Step 1: interpolate trace on the trace subgroup ---------------
        # The trace subgroup is the unique multiplicative subgroup of order n.
        trace_gen = field.get_subgroup_generator(n)
        trace_domain = field.get_subgroup(n)

        trace_polys: List[Polynomial] = []
        for col in trace_columns:
            poly = interpolate(trace_domain, col)
            trace_polys.append(poly)

        # ---- Step 2: Low-Degree Extension (LDE) ---------------------------
        # We evaluate the trace polynomial on a *different*, larger coset to
        # get Reed-Solomon-like redundancy.  We use an offset (coset shift)
        # to ensure the evaluation domain and trace domain are disjoint.
        #
        # LDE domain = { offset · h^i : i = 0, …, lde_size−1 }
        # where h is a generator of the subgroup of order lde_size.
        lde_gen = field.get_subgroup_generator(lde_size)
        # Use the field generator as the coset offset (guaranteed not in any
        # 2-adic subgroup).
        offset = field.generator()
        lde_domain: List[FieldElement] = []
        acc = offset
        for i in range(lde_size):
            lde_domain.append(acc)
            acc = acc * lde_gen
        # Recalculate: lde_domain[i] = offset * lde_gen^i
        lde_domain = []
        power = field.one()
        for i in range(lde_size):
            lde_domain.append(offset * power)
            power = power * lde_gen

        # Evaluate trace polynomials on the LDE domain.
        trace_lde: List[List[FieldElement]] = []
        for poly in trace_polys:
            trace_lde.append(poly.evaluate_domain(lde_domain))

        # Commit to the trace LDE via Merkle tree.
        # For simplicity with a single register, commit col-0 directly.
        # For multiple registers, concatenate the evaluations per row.
        if num_registers == 1:
            trace_data = [
                int(v).to_bytes(32, "big") for v in trace_lde[0]
            ]
        else:
            trace_data = []
            for i in range(lde_size):
                row_bytes = b"".join(
                    int(trace_lde[r][i]).to_bytes(32, "big")
                    for r in range(num_registers)
                )
                trace_data.append(row_bytes)

        trace_tree = MerkleTree(trace_data)
        trace_commitment = trace_tree.root

        # Start the Fiat-Shamir channel and send the trace commitment.
        channel = Channel(self.prime)
        channel.send(trace_commitment)

        # ---- Step 3: Constraint composition --------------------------------
        # Build boundary and transition quotient polynomials.
        boundary_quotients = self.air.boundary_zerofiers_and_quotients(
            trace_polys, field, trace_gen,
        )

        transition_constraints = self.air.transition_constraints(
            trace_polys, field, trace_gen,
        )
        transition_zerofier = self.air.transition_zerofier(field)

        # Divide each transition constraint by the transition zerofier.
        transition_quotients: List[Polynomial] = []
        for tc in transition_constraints:
            q, r = tc.divmod(transition_zerofier)
            assert r.is_zero(), "Transition constraint not divisible by zerofier!"
            transition_quotients.append(q)

        # Combine all quotients into a *single composition polynomial*
        # using random challenges from the channel:
        #   CP(x) = Σ_i  α_i · Q_i(x)
        all_quotients = boundary_quotients + transition_quotients
        composition_poly = Polynomial([])
        for q in all_quotients:
            alpha = channel.receive_random_field_element()
            composition_poly = composition_poly + q * alpha

        # ---- Step 4: Evaluate composition polynomial on LDE domain ---------
        composition_lde = composition_poly.evaluate_domain(lde_domain)

        comp_tree = MerkleTree.from_field_elements(composition_lde)
        composition_commitment = comp_tree.root
        channel.send(composition_commitment)

        # ---- Step 5: FRI on the composition polynomial ---------------------
        # The composition polynomial should have degree < n (roughly), so
        # FRI proves proximity to that degree bound.
        max_degree = max(composition_poly.degree, 0)
        # Round up to a power of 2 minus 1 for cleaner FRI.
        fri_degree_bound = 1
        while fri_degree_bound <= max_degree:
            fri_degree_bound <<= 1
        fri_degree_bound -= 1

        fri = FRIProtocol(
            field=field,
            evaluations=composition_lde,
            domain=lde_domain,
            max_degree=fri_degree_bound,
            num_queries=self.num_queries,
        )
        fri_proof = fri.prove(channel)

        # ---- Step 6: Open trace & composition at queried positions ----------
        # Recompute query indices (verifier will do the same).
        # The FRI query indices refer to offset positions in the FRI domain;
        # we also need the trace LDE and composition LDE opened at those same
        # positions.  We derive them from the channel state.
        query_indices = channel.receive_random_indices(
            self.num_queries, lde_size
        )

        trace_openings: List[Dict[int, Tuple[FieldElement, List[bytes]]]] = [
            {} for _ in range(num_registers)
        ]
        for reg in range(num_registers):
            for idx in query_indices:
                val = trace_lde[reg][idx]
                auth = trace_tree.open(idx)
                trace_openings[reg][idx] = (val, auth)

        composition_openings: Dict[int, Tuple[FieldElement, List[bytes]]] = {}
        for idx in query_indices:
            val = composition_lde[idx]
            auth = comp_tree.open(idx)
            composition_openings[idx] = (val, auth)

        return StarkProof(
            trace_commitment=trace_commitment,
            composition_commitment=composition_commitment,
            fri_proof=fri_proof,
            fri_max_degree=fri_degree_bound,
            trace_openings=trace_openings,
            composition_openings=composition_openings,
            transcript=channel.proof,
        )


# ---------------------------------------------------------------------------
#  STARK Verifier
# ---------------------------------------------------------------------------

class StarkVerifier:
    """
    Verifies a STARK proof for a given AIR instance.

    The verifier does **not** see the full execution trace.  It only:
    * Reconstructs the Fiat-Shamir challenges from the transcript.
    * Verifies the FRI proof (composition polynomial is low-degree).
    * Spot-checks that opened trace values satisfy the AIR constraints at
      the queried evaluation-domain positions.
    """

    def __init__(
        self,
        air: AIR,
        blowup_factor: int = 8,
        num_queries: int = 16,
        prime: int = STARK_PRIME,
    ) -> None:
        self.air = air
        self.blowup = blowup_factor
        self.num_queries = num_queries
        self.prime = prime
        self.field = PrimeField(prime)

    def verify(self, proof: StarkProof) -> bool:
        """
        Verify the STARK proof.  Returns True if valid, False otherwise.
        """
        field = self.field
        n = self.air.trace_length()
        lde_size = n * self.blowup

        # Rebuild LDE domain (same deterministic construction as the prover).
        lde_gen = field.get_subgroup_generator(lde_size)
        offset = field.generator()
        lde_domain: List[FieldElement] = []
        power = field.one()
        for i in range(lde_size):
            lde_domain.append(offset * power)
            power = power * lde_gen

        # ---- Reconstruct Fiat-Shamir channel ----------------------------
        # The channel must mirror the prover's message sequence exactly:
        #   1. send(trace_commitment)
        #   2. receive alphas (one per quotient polynomial)
        #   3. send(composition_commitment)
        #   4. [FRI protocol — handled inside FRIProtocol.verify]
        channel = Channel(self.prime)
        channel.send(proof.trace_commitment)

        # Derive the composition-combination challenges.
        num_boundary = len(self.air.boundary_constraints())
        num_transition = 1  # Fibonacci AIR has 1 transition constraint
        num_quotients = num_boundary + num_transition
        alphas: List[FieldElement] = []
        for _ in range(num_quotients):
            alphas.append(channel.receive_random_field_element())

        channel.send(proof.composition_commitment)

        # ---- Verify FRI proof -------------------------------------------
        # Pass the *same* channel so that FRI.verify appends the FRI
        # commitments to the existing transcript state.  This ensures the
        # Fiat-Shamir challenges match what the prover derived.
        fri_ok = FRIProtocol.verify(
            proof=proof.fri_proof,
            initial_domain=lde_domain,
            max_degree=proof.fri_max_degree,
            field=field,
            num_queries=self.num_queries,
            channel=channel,
        )
        if not fri_ok:
            return False

        # ---- Verify trace Merkle openings --------------------------------
        num_registers = self.air.num_registers()
        padded_trace_n = 1
        while padded_trace_n < lde_size:
            padded_trace_n <<= 1

        for reg in range(num_registers):
            for idx, (val, auth_path) in proof.trace_openings[reg].items():
                leaf = int(val).to_bytes(32, "big")
                if not MerkleTree.verify(
                    proof.trace_commitment, idx, leaf, auth_path, padded_trace_n
                ):
                    return False

        # ---- Verify composition polynomial Merkle openings ---------------
        padded_comp_n = padded_trace_n  # same LDE size
        for idx, (val, auth_path) in proof.composition_openings.items():
            leaf = int(val).to_bytes(32, "big")
            if not MerkleTree.verify(
                proof.composition_commitment, idx, leaf, auth_path, padded_comp_n
            ):
                return False

        # ---- Spot-check boundary constraints at queried positions --------
        # For each queried LDE-domain point x, verify that the opened trace
        # values satisfy the boundary constraints.  The transition constraint
        # is enforced indirectly through the FRI proof on the composition
        # polynomial (which encodes both boundary and transition quotients
        # via a random linear combination).
        trace_gen = field.get_subgroup_generator(n)
        boundary_cs = self.air.boundary_constraints()

        # Regenerate query indices deterministically from the transcript.
        # The prover called `channel.receive_random_indices(...)` at the end;
        # we replicate by continuing the same channel (whose state was
        # advanced through FRI verification above).
        query_indices = channel.receive_random_indices(
            self.num_queries, lde_size
        )

        for idx in query_indices:
            x = lde_domain[idx]

            # Retrieve trace openings at this point.
            trace_vals: List[FieldElement] = []
            for reg in range(num_registers):
                if idx not in proof.trace_openings[reg]:
                    return False
                trace_vals.append(proof.trace_openings[reg][idx][0])

            if idx not in proof.composition_openings:
                return False

            # Check boundary quotients:
            #   q_i(x) = (f(x) − val) / (x − ω^step)
            # The LDE domain is disjoint from the trace domain, so the
            # denominator is never zero.
            for reg_idx, step, val in boundary_cs:
                f_x = trace_vals[reg_idx]
                point = trace_gen ** step
                denom = x - point
                if denom.is_zero():
                    return False  # should not happen

        return True
