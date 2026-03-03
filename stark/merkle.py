"""
snarks.merkle - Merkle-tree commitment scheme.

Mathematical background
-----------------------
A **Merkle tree** lets us commit to a list of n values with a single hash
(the *root*).  Later we can reveal any single leaf together with a short
(O(log n)) **authentication path** (a.k.a. *decommitment*), and the verifier
can check that the leaf is consistent with the root - without seeing the
other leaves.

In STARKs the prover evaluates a polynomial on a large domain and commits to
the vector of evaluations by building a Merkle tree.  The verifier later
"queries" random positions; for each query the prover opens the corresponding
leaf with its authentication path.

The module is built around an **Abstract Base Class** for the hash function
so that SHA-256 can be swapped for e.g. BLAKE3, Poseidon, etc.

Implementation details
* Leaf count is padded to the next power of 2 with zero-bytes.
* Tree is stored as a flat list of length 2n (index 1 = root).
"""

from __future__ import annotations

import abc
import hashlib
from typing import List, Sequence, Tuple


# ---------------------------------------------------------------------------
# Abstract hash interface - swap this to change the hash function
# ---------------------------------------------------------------------------

class BaseHash(abc.ABC):
    """Interface for a hash function used inside the Merkle tree."""

    @abc.abstractmethod
    def hash_leaf(self, data: bytes) -> bytes:
        """Hash a single leaf value."""
        ...

    @abc.abstractmethod
    def hash_node(self, left: bytes, right: bytes) -> bytes:
        """Hash two child nodes to produce a parent node."""
        ...


class SHA256Hash(BaseHash):
    """Default SHA-256 based hash."""

    def hash_leaf(self, data: bytes) -> bytes:
        # Domain-separate leaves from internal nodes with a 0x00 prefix.
        return hashlib.sha256(b"\x00" + data).digest()

    def hash_node(self, left: bytes, right: bytes) -> bytes:
        # Domain-separate internal nodes with a 0x01 prefix.
        return hashlib.sha256(b"\x01" + left + right).digest()


# ---------------------------------------------------------------------------
# MerkleTree
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Merkle-tree commitment over a list of byte-string leaves.

    After construction the ``root`` property gives the binding commitment.
    ``open(index)`` returns the authentication path for ``leaves[index]``.
    ``verify_static`` checks an opening against a given root.

    The tree is stored in a *flat array* of size ``2 * padded_n`` where
    ``tree[1]`` is the root and ``tree[padded_n + i]`` is the i-th leaf.
    """

    def __init__(
        self,
        data: Sequence[bytes],
        hasher: BaseHash | None = None,
    ) -> None:
        self.hasher: BaseHash = hasher or SHA256Hash()
        self.n = len(data)

        # Pad to next power of 2
        self.padded_n = 1
        while self.padded_n < self.n:
            self.padded_n <<= 1

        empty_hash = self.hasher.hash_leaf(b"")
        self.tree: list[bytes] = [b""] * (2 * self.padded_n)

        # Fill leaves
        for i in range(self.padded_n):
            if i < self.n:
                self.tree[self.padded_n + i] = self.hasher.hash_leaf(data[i])
            else:
                self.tree[self.padded_n + i] = empty_hash

        # Build internal nodes bottom-up
        for i in range(self.padded_n - 1, 0, -1):
            self.tree[i] = self.hasher.hash_node(
                self.tree[2 * i], self.tree[2 * i + 1]
            )

    # ----- commitment (the root hash) -------------------------------------

    @property
    def root(self) -> bytes:
        """Return the Merkle root - a binding commitment to all leaves."""
        return self.tree[1]

    # ----- opening (authentication path) -----------------------------------

    def open(self, index: int) -> List[bytes]:
        """
        Return the authentication path for ``leaves[index]``.

        The path is a list of sibling hashes from the leaf up to (but not
        including) the root.  ``path[0]`` is the sibling of the leaf,
        ``path[1]`` is the sibling of the leaf's parent, etc.
        """
        assert 0 <= index < self.n, f"Index {index} out of range [0, {self.n})."
        idx = self.padded_n + index
        path: list[bytes] = []
        while idx > 1:
            sibling = idx ^ 1  # flip the last bit to get the sibling
            path.append(self.tree[sibling])
            idx >>= 1
        return path

    # ----- static verification ---------------------------------------------

    @staticmethod
    def verify(
        root: bytes,
        index: int,
        leaf_data: bytes,
        auth_path: List[bytes],
        padded_n: int,
        hasher: BaseHash | None = None,
    ) -> bool:
        """
        Verify that ``leaf_data`` at position ``index`` is consistent with
        ``root`` given the authentication ``auth_path``.

        This is a **static** method - it does not require the full tree.
        """
        h = hasher or SHA256Hash()
        current = h.hash_leaf(leaf_data)
        idx = padded_n + index

        for sibling_hash in auth_path:
            if idx & 1 == 0:
                # current node is a left child
                current = h.hash_node(current, sibling_hash)
            else:
                # current node is a right child
                current = h.hash_node(sibling_hash, current)
            idx >>= 1

        return current == root

    # ----- convenience: commit a list of FieldElements --------------------

    @classmethod
    def from_field_elements(
        cls,
        elements: Sequence,  # Sequence[FieldElement] - avoid circular import
        hasher: BaseHash | None = None,
    ) -> "MerkleTree":
        """
        Build a Merkle tree from a sequence of ``FieldElement`` objects.
        Each element is serialized as its integer value in 32-byte big-endian.
        """
        data = [int(e).to_bytes(32, "big") for e in elements]
        return cls(data, hasher)
