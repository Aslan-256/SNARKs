# snarks — A pedagogical zk-STARK implementation in Python.
#
# This package provides a modular, from-scratch implementation of the
# STARK (Scalable Transparent Argument of Knowledge) proof system.
#
# Modules:
#   field       – Finite-field arithmetic (prime fields & extensions).
#   polynomial  – Polynomial representation, evaluation, interpolation, FFT.
#   merkle      – Merkle-tree commitment scheme (SHA-256 default).
#   channel     – Fiat-Shamir non-interactive channel.
#   air         – Algebraic Intermediate Representation (Fibonacci AIR).
#   fri         – FRI (Fast Reed-Solomon IOP of Proximity) protocol.
#   stark       – Top-level Prover / Verifier orchestration.

from snarks.field import PrimeField, FieldElement
from snarks.polynomial import Polynomial
from snarks.merkle import MerkleTree
from snarks.channel import Channel
from snarks.air import FibonacciAIR
from snarks.fri import FRIProtocol
from snarks.stark import StarkProver, StarkVerifier

__all__ = [
    "PrimeField",
    "FieldElement",
    "Polynomial",
    "MerkleTree",
    "Channel",
    "FibonacciAIR",
    "FRIProtocol",
    "StarkProver",
    "StarkVerifier",
]
