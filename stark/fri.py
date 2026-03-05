"""
snarks.fri - FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity).

Mathematical background
-----------------------
The **FRI** protocol is the heart of STARK soundness.  Given a committed
vector of field-element evaluations, FRI convinces a verifier that the
underlying function is "close" to a polynomial of degree < D - i.e. that the
evaluations sit on (or very near) a low-degree polynomial.

The protocol works in **rounds**.  In each round the current polynomial
f(x) of degree < D is "folded" into a polynomial f'(y) of degree < D/2
by a random verifier challenge a:

    f'(y) = f_even(y) + a · f_odd(y)

where f(x) = f_even(x²) + x · f_odd(x²).

Geometrically, the evaluation domain (a multiplicative coset) is *squared*
in each round, mapping  {d, -d}  pairs to the same point d²  - which is why
the folded evaluation domain is half the size.

After O(log D) rounds the degree bound reaches a small constant and the
prover sends the final (constant) polynomial in the clear.  The verifier
checks consistency at randomly queried positions through every layer.

Detailed steps
--------------
1. **Commit phase** - for each layer the prover computes evaluations of the
   folded polynomial on the new (halved) domain and commits with a Merkle
   tree.
2. **Query phase** - the verifier picks random indices and, for each layer,
   asks for the two evaluations f(d) and f(-d) together with their Merkle
   authentication paths.  It checks that the folding relation holds:
       f_next(d²) = (f(d) + f(-d)) / 2 + a · (f(d) - f(-d)) / (2d)
3. **Final check** - the last-layer polynomial (degree 0, i.e. a constant)
   is verified directly.

Index tracking
--------------
When folding layer *r*, the pair  (idx, idx + half_r)  produces a result at
position ``idx`` in layer *r + 1*.  In the *next* layer (of size ``half_r``),
the pairs are  (j, j + half_{r+1})  where ``half_{r+1} = half_r / 2``.

If idx < half_{r+1} the fold result is at the "primary" position of the
next pair, i.e. it equals ``layer_proofs[r+1].value``.  If
idx ≥ half_{r+1} the fold result lands at the "sibling" position, i.e. it
equals ``layer_proofs[r+1].sibling_value``.

We must account for this when the verifier compares the expected fold value
against the actually opened leaf in the next layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple

from stark.field import FieldElement, PrimeField, STARK_PRIME
from stark.merkle import MerkleTree
from stark.channel import Channel


# ---------------------------------------------------------------------------
#  Data structures for a FRI proof
# ---------------------------------------------------------------------------

@dataclass
class FRILayerProof:
    """Proof data for a single FRI query at one layer."""
    index: int                  # primary index (always in the first half)
    value: FieldElement         # f(domain[index])
    sibling_value: FieldElement # f(domain[index + half])  (the partner)
    auth_path: List[bytes]      # Merkle path for value
    sibling_auth_path: List[bytes]  # Merkle path for sibling_value


@dataclass
class FRIProof:
    """Complete FRI proof."""
    # Per-layer Merkle roots (layer 0 is the original evaluation).
    commitments: List[bytes]
    # The folding challenges a_0, a_1, … used in each round.
    alphas: List[FieldElement]
    # For each query index: list-of-layers of FRILayerProof.
    query_proofs: List[List[FRILayerProof]]
    # The constant polynomial (last layer value).
    final_value: FieldElement


# ---------------------------------------------------------------------------
#  Helper: compute number of folding rounds from a degree bound
# ---------------------------------------------------------------------------

def _num_fri_rounds(max_degree: int) -> int:
    """Return the number of folding rounds needed for a given max degree."""
    degree_bound = max_degree + 1  # number of coefficients
    n = 0
    while degree_bound > 1:
        degree_bound //= 2
        n += 1
    return n


# ---------------------------------------------------------------------------
#  FRI Protocol
# ---------------------------------------------------------------------------

class FRIProtocol:
    """
    Implements the FRI commit-and-query protocol.

    Parameters
    ----------
    field : PrimeField
        The field in which all arithmetic happens.
    evaluations : list[FieldElement]
        Evaluations of the polynomial on the *initial* evaluation domain
        (a multiplicative coset of size ``len(evaluations)``).
    domain : list[FieldElement]
        The evaluation domain points (coset elements).
        **Layout requirement**: ``domain[j + len/2] = -domain[j]`` for
        j in the first half.  This is automatically satisfied for cosets
        of multiplicative subgroups of even order.
    max_degree : int
        Upper bound on the degree of the polynomial whose proximity is
        being tested.  After ``ceil(log2(max_degree + 1))`` folding
        rounds the polynomial should reduce to a constant.
    num_queries : int
        Number of random query positions.
    """

    def __init__(
        self,
        field: PrimeField,
        evaluations: List[FieldElement],
        domain: List[FieldElement],
        max_degree: int,
        num_queries: int = 8,
    ) -> None:
        assert len(evaluations) == len(domain), (
            "evaluations and domain must have the same size"
        )
        self.field = field
        self.initial_evaluations = evaluations
        self.initial_domain = domain
        self.max_degree = max_degree
        self.num_queries = num_queries

    # =====================================================================
    #  PROVER
    # =====================================================================

    def prove(self, channel: Channel) -> FRIProof:
        """
        Run the FRI commit phase and query phase, writing to *channel*.
        Returns a ``FRIProof`` object.
        """
        # ----- commit phase ------------------------------------------------
        layers_evals: List[List[FieldElement]] = [self.initial_evaluations]
        layers_domains: List[List[FieldElement]] = [self.initial_domain]
        commitments: List[bytes] = []
        alphas: List[FieldElement] = []

        current_evals = list(self.initial_evaluations)
        current_domain = list(self.initial_domain)

        # Commit to initial evaluations.
        tree = MerkleTree.from_field_elements(current_evals)
        commitments.append(tree.root)
        channel.send(tree.root)
        trees: List[MerkleTree] = [tree]

        num_rounds = _num_fri_rounds(self.max_degree)

        for _ in range(num_rounds):
            # Receive folding challenge from the (Fiat-Shamir) verifier.
            alpha = channel.receive_random_field_element()
            alphas.append(alpha)

            # --- fold evaluations ------------------------------------------
            n = len(current_evals)
            half = n // 2
            new_evals: List[FieldElement] = []
            new_domain: List[FieldElement] = []
            two = self.field(2)

            for j in range(half):
                # domain[j] and domain[j + half] are "partners":
                #   domain[j + half] = -domain[j]
                # because the domain is a coset of a multiplicative subgroup
                # whose generator raised to half the order equals -1.
                f_pos = current_evals[j]           # f(d)
                f_neg = current_evals[j + half]    # f(-d)
                d = current_domain[j]

                # FRI folding formula:
                #   f_even = (f(d) + f(-d)) / 2
                #   f_odd  = (f(d) - f(-d)) / (2d)
                #   f'(d²) = f_even + a · f_odd
                f_even = (f_pos + f_neg) / two
                f_odd = (f_pos - f_neg) / (two * d)
                new_evals.append(f_even + alpha * f_odd)
                new_domain.append(d * d)  # d²

            current_evals = new_evals
            current_domain = new_domain
            layers_evals.append(current_evals)
            layers_domains.append(current_domain)

            # Commit to the new layer.
            tree = MerkleTree.from_field_elements(current_evals)
            commitments.append(tree.root)
            channel.send(tree.root)
            trees.append(tree)

        # After all folds the polynomial is constant; every evaluation in
        # the last layer should be equal.  Send one value as final_value.
        final_value = current_evals[0]
        channel.send(int(final_value).to_bytes(32, "big"))

        # ----- query phase --------------------------------------------------
        # Sample random query positions in the first half of the initial
        # domain (the second half is implicitly determined as the partner).
        initial_half = len(self.initial_evaluations) // 2
        query_indices = channel.receive_random_indices(
            self.num_queries, initial_half
        )

        query_proofs: List[List[FRILayerProof]] = []
        for qi in query_indices:
            layer_proofs: List[FRILayerProof] = []
            # `fold_pos` tracks where the last fold result lives in the
            # current layer.  For the first layer this is just the query
            # index (which is already in the first half).
            fold_pos = qi

            for layer_idx in range(num_rounds):
                evals = layers_evals[layer_idx]
                half = len(evals) // 2

                # The pair to open is (primary, primary + half) where
                # `primary = fold_pos % half`.  This ensures the primary
                # index is always in the first half [0, half).
                primary = fold_pos % half
                partner = primary + half

                layer_proofs.append(FRILayerProof(
                    index=primary,
                    value=evals[primary],
                    sibling_value=evals[partner],
                    auth_path=trees[layer_idx].open(primary),
                    sibling_auth_path=trees[layer_idx].open(partner),
                ))

                # After folding (primary, partner) in layer `layer_idx`,
                # the result lands at position `primary` in the next layer.
                fold_pos = primary

            query_proofs.append(layer_proofs)

        return FRIProof(
            commitments=commitments,
            alphas=alphas,
            query_proofs=query_proofs,
            final_value=final_value,
        )

    # =====================================================================
    #  VERIFIER
    # =====================================================================

    @staticmethod
    def verify(
        proof: FRIProof,
        initial_domain: List[FieldElement],
        max_degree: int,
        field: PrimeField,
        num_queries: int = 8,
        channel: Channel | None = None,
    ) -> bool:
        """
        Verify a FRI proof.

        The verifier replays the FRI transcript on *channel* (or a fresh
        one if not provided), deriving the same challenges, and checks the
        query openings.

        Parameters
        ----------
        channel : Channel | None
            If provided, the channel **continues** from whatever state the
            caller has already built (e.g. the STARK layer feeds trace and
            composition commitments before calling FRI).  If *None*, a fresh
            channel is created - suitable for standalone FRI verification.

        Returns True if all checks pass.
        """
        commitments = proof.commitments
        alphas = proof.alphas
        num_rounds = _num_fri_rounds(max_degree)

        # --- replay FRI-specific transcript entries on the channel ---------
        ch = channel if channel is not None else Channel(field.prime)
        ch.send(commitments[0])  # initial layer commitment

        for r in range(num_rounds):
            expected_alpha = ch.receive_random_field_element()
            if expected_alpha != alphas[r]:
                return False
            ch.send(commitments[r + 1])

        # Final value.
        ch.send(int(proof.final_value).to_bytes(32, "big"))

        # --- regenerate query indices --------------------------------------
        initial_half = len(initial_domain) // 2
        query_indices = ch.receive_random_indices(
            num_queries, initial_half
        )

        if len(proof.query_proofs) != len(query_indices):
            return False

        # --- build successive domains (by squaring the first half) ---------
        domains: List[List[FieldElement]] = [initial_domain]
        current_dom = list(initial_domain)
        for _ in range(num_rounds):
            half = len(current_dom) // 2
            current_dom = [current_dom[j] * current_dom[j] for j in range(half)]
            domains.append(current_dom)

        # --- check each query through all layers ---------------------------
        two = field(2)

        for q_idx, qi in enumerate(query_indices):
            layer_proofs = proof.query_proofs[q_idx]
            if len(layer_proofs) != num_rounds:
                return False

            # `fold_pos` mirrors the prover's tracking: it records where
            # the fold result from the *previous* round sits in the
            # current layer.  For the first layer it is just `qi`.
            fold_pos = qi

            for r in range(num_rounds):
                lp = layer_proofs[r]
                dom = domains[r]
                half = len(dom) // 2

                # --- Merkle verification -----------------------------------
                padded_n = 1
                while padded_n < len(dom):
                    padded_n <<= 1

                val_bytes = int(lp.value).to_bytes(32, "big")
                sib_bytes = int(lp.sibling_value).to_bytes(32, "big")

                if not MerkleTree.verify(
                    commitments[r], lp.index, val_bytes,
                    lp.auth_path, padded_n
                ):
                    return False
                if not MerkleTree.verify(
                    commitments[r], lp.index + half, sib_bytes,
                    lp.sibling_auth_path, padded_n
                ):
                    return False

                # --- cross-layer consistency (previous fold → this layer) --
                # For r > 0, verify that the fold result from the previous
                # round matches the value opened in *this* layer.
                # The fold result sits at position `fold_pos` which is either
                # the primary (lp.index) or the sibling (lp.index + half).
                if r > 0:
                    if fold_pos == lp.index:
                        opened_here = lp.value
                    else:
                        opened_here = lp.sibling_value
                    if prev_expected != opened_here:  # noqa: F821
                        return False

                # --- compute the expected fold result ----------------------
                d = dom[lp.index]
                f_pos = lp.value
                f_neg = lp.sibling_value
                alpha = alphas[r]

                f_even = (f_pos + f_neg) / two
                f_odd = (f_pos - f_neg) / (two * d)
                prev_expected = f_even + alpha * f_odd  # noqa: F841

                # After folding, the result sits at position `lp.index`
                # in the next layer.
                fold_pos = lp.index

            # After the last round, the fold result should equal the
            # committed final constant.
            if prev_expected != proof.final_value:  # noqa: F821
                return False

        return True
