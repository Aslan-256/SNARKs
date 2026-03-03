"""
snarks.channel – Fiat-Shamir non-interactive channel.

Mathematical background
-----------------------
The **Fiat-Shamir heuristic** transforms an *interactive* proof system into a
*non-interactive* one.  Instead of a verifier choosing random challenges, the
prover derives each challenge deterministically from a hash of the entire
transcript so far.  The resulting protocol is secure in the **Random Oracle
Model** (ROM).

Implementation
--------------
We maintain an internal running hash (SHA-256 by default) that accumulates
every piece of data the prover "sends" to the verifier.  When a challenge is
needed we hash the current state and read field elements / random bytes from
the output.
"""

from __future__ import annotations

import hashlib
from typing import List

from snarks.field import FieldElement, STARK_PRIME


class Channel:
    """
    Simulated verifier channel implementing the Fiat-Shamir transform.

    Usage (prover side)::

        ch = Channel()
        ch.send(commitment_bytes)       # add data to transcript
        alpha = ch.receive_random_field_element()  # derive challenge
        ch.send(next_commitment_bytes)
        beta  = ch.receive_random_field_element()
        ...

    The verifier reconstructs the *same* ``Channel`` object, feeds the
    same commitments in order, and checks that the challenges match.
    """

    def __init__(self, prime: int = STARK_PRIME) -> None:
        self.prime = prime
        # Internal transcript state — we keep a running SHA-256 hash.
        self._state: bytes = b""
        # Also keep a full list of proof objects for serialisation.
        self.proof: List[bytes] = []

    # ----- transcript manipulation ----------------------------------------

    def send(self, data: bytes) -> None:
        """
        Append *data* to the transcript.

        This models the prover sending a message (e.g. a Merkle root,
        polynomial commitment, or evaluation) to the verifier.
        """
        self._state = hashlib.sha256(self._state + data).digest()
        self.proof.append(data)

    def _squeeze(self) -> bytes:
        """
        Derive 32 pseudo-random bytes from the current state and advance
        the state (so the next squeeze gives different output).
        """
        result = hashlib.sha256(self._state + b"squeeze").digest()
        # Advance state so repeated squeezes yield independent outputs.
        self._state = hashlib.sha256(self._state + b"advance").digest()
        return result

    # ----- deriving challenges --------------------------------------------

    def receive_random_field_element(self) -> FieldElement:
        """
        Derive a uniformly-random-looking field element from the transcript.

        Converts 32 bytes to an integer and reduces modulo the field prime.
        (Negligible statistical bias for primes ≪ 2^{256}.)
        """
        raw = self._squeeze()
        value = int.from_bytes(raw, "big") % self.prime
        return FieldElement(value, self.prime)

    def receive_random_int(self, lo: int, hi: int) -> int:
        """
        Derive a random integer in ``[lo, hi)`` from the transcript.

        Used when sampling query indices for FRI.
        """
        raw = self._squeeze()
        value = int.from_bytes(raw, "big")
        return lo + (value % (hi - lo))

    def receive_random_indices(self, n: int, domain_size: int) -> List[int]:
        """
        Draw *n* distinct random indices in ``[0, domain_size)``.
        If collisions occur, re-squeeze until we have *n* unique indices.
        """
        indices: set[int] = set()
        while len(indices) < n:
            idx = self.receive_random_int(0, domain_size)
            indices.add(idx)
        return sorted(indices)
