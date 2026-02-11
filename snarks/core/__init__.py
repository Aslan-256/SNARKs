"""Core module containing fundamental mathematical structures for zkSNARKs."""

from .finite_field import FiniteField
from .polynomial import Polynomial
from .circuit import ArithmeticCircuit, Wire, Gate, GateType
from .arithmetization import Arithmetization, R1CS, QAPInstance

__all__ = [
    'FiniteField',
    'Polynomial',
    'ArithmeticCircuit',
    'Wire',
    'Gate',
    'GateType',
    'Arithmetization',
    'R1CS',
    'QAPInstance',
]
