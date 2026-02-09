"""
SNARKs: Simplified, theory-based implementations of zk-SNARK proof systems.

This package provides educational implementations of various zero-knowledge
proof systems including PCP, QAP, LIP, and PIOP.
"""

__version__ = "0.1.0"

from .core.finite_field import FiniteField
from .core.polynomial import Polynomial

__all__ = ["FiniteField", "Polynomial", "__version__"]
