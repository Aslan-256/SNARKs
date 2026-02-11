"""
Cryptographic Primitives for zkSNARKs.

This package contains foundational cryptographic primitives used across
various zero-knowledge proof constructions.

Modules:
    merkle: Squashed Merkle Trees for commitment and authentication
    pir: Simulated Private Information Retrieval
    fiat_shamir: Transcript management for Fiat-Shamir transformation
    commitments: Polynomial, Vector, and Inner Product Commitment Schemes
"""

from .merkle import MerkleTree
from .pir import SimulatedPIR
from .fiat_shamir import Transcript
from .commitments import (
    CommitmentScheme,
    KZGCommitment,
    KZGSetup,
    PedersenVectorCommitment,
    PedersenSetup,
    SimulatedBilinearGroup,
)

__all__ = [
    'MerkleTree',
    'SimulatedPIR',
    'Transcript',
    'CommitmentScheme',
    'KZGCommitment',
    'KZGSetup',
    'PedersenVectorCommitment',
    'PedersenSetup',
    'SimulatedBilinearGroup',
]
