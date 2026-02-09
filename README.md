# SNARKs - Zero-Knowledge Proof Systems

A modular Python implementation of simplified, theory-based zero-knowledge proof systems for educational purposes. This repository implements four fundamental approaches to zero-knowledge proofs:

- **PCP** - Probabilistically Checkable Proofs
- **QAP** - Quadratic Arithmetic Programs  
- **LIP** - Linear Interactive Proofs
- **PIOP** - Polynomial Interactive Oracle Proofs

> **Note**: This is an educational implementation focusing on theory and concepts. It does not include real-world cryptographic engineering such as elliptic curve pairings or production-ready security.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Theory Overview](#theory-overview)
- [Project Structure](#project-structure)
- [Usage Examples](#usage-examples)
- [Running Tests](#running-tests)
- [Benchmarks](#benchmarks)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

✅ **Clean Object-Oriented Design**: Well-structured classes with clear separation of concerns  
✅ **Type Hints**: Full type annotations for better code clarity and IDE support  
✅ **Comprehensive Documentation**: Detailed docstrings in English for all classes and methods  
✅ **Core Mathematical Modules**: Finite field and polynomial arithmetic implementations  
✅ **Four Proof Systems**: PCP, QAP, LIP, and PIOP with setup/prove/verify interfaces  
✅ **Unit Tests**: Extensive test coverage using pytest  
✅ **Benchmarks**: Performance measurements for all operations  
✅ **Examples**: Practical examples demonstrating each proof system  

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### From Source

```bash
# Clone the repository
git clone https://github.com/Aslan-256/SNARKs.git
cd SNARKs

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Dependencies

- `numpy` - For numerical operations (optional, but recommended)
- `pytest` - For running tests
- `pytest-benchmark` - For performance benchmarking

## Quick Start

```python
from snarks.proofs.qap import QAP

# Setup: Create a QAP for a simple circuit (x * y = z)
setup = QAP.setup(modulus=97)

# Prove: Generate a proof with witness [1, x=3, y=4, z=12]
witness = [1, 3, 4, 12]
proof = QAP.prove(setup, witness)

# Verify: Check the proof with public inputs
public_inputs = [1, 12]
is_valid = QAP.verify(setup, proof, public_inputs)
print(f"Proof valid: {is_valid}")  # Output: Proof valid: True
```

## Theory Overview

### What are Zero-Knowledge Proofs?

Zero-knowledge proofs allow a **prover** to convince a **verifier** that a statement is true without revealing any information beyond the validity of the statement itself.

### Proof Systems Implemented

#### 1. PCP (Probabilistically Checkable Proofs)

**Core Idea**: A proof can be verified by reading only a small, random subset of its bits.

- **Setup**: Define field parameters and constraints
- **Prove**: Create a proof string encoding the witness
- **Verify**: Check consistency by querying random positions

**Use Case**: Foundation for modern SNARKs; demonstrates probabilistic verification.

#### 2. QAP (Quadratic Arithmetic Programs)

**Core Idea**: Transform arithmetic circuits into polynomial equations over finite fields.

- **Setup**: Convert circuit to polynomials (A, B, C) and target polynomial t(x)
- **Prove**: Compute quotient polynomial H such that A·B - C = H·t
- **Verify**: Check polynomial divisibility

**Use Case**: Used in zkSNARKs like Pinocchio and Groth16.

**Mathematical Foundation**:
```
Circuit constraint: x * y = z
QAP encoding: A(s)·B(s) - C(s) = H(s)·t(s)
where s is a secret point
```

#### 3. LIP (Linear Interactive Proofs)

**Core Idea**: Interactive protocol where verifier sends linear queries and prover responds.

- **Setup**: Define field and interaction parameters
- **Prove**: Commit to witness and respond to challenges
- **Verify**: Check linear consistency constraints

**Use Case**: Demonstrates interactive proof concepts; basis for arguments.

**Protocol**:
1. Prover commits to witness
2. Verifier sends random linear combinations
3. Prover responds with evaluations
4. Verifier checks consistency

#### 4. PIOP (Polynomial Interactive Oracle Proofs)

**Core Idea**: Combine polynomial commitments with interactive proofs.

- **Setup**: Define polynomial degree bounds
- **Prove**: Create polynomial oracles encoding the witness
- **Verify**: Query polynomials at random points

**Use Case**: Modern SNARKs like PLONK and Marlin use PIOP techniques.

**Advantages**:
- Universal setup (circuit-independent)
- Efficient polynomial checking
- Foundation for transparent SNARKs

## Project Structure

```
SNARKs/
├── snarks/                    # Main package
│   ├── __init__.py
│   ├── core/                  # Core mathematical modules
│   │   ├── __init__.py
│   │   ├── finite_field.py    # Finite field arithmetic
│   │   └── polynomial.py      # Polynomial operations
│   ├── proofs/                # Proof system implementations
│   │   ├── __init__.py
│   │   ├── pcp.py            # Probabilistically Checkable Proofs
│   │   ├── qap.py            # Quadratic Arithmetic Programs
│   │   ├── lip.py            # Linear Interactive Proofs
│   │   └── piop.py           # Polynomial Interactive Oracle Proofs
│   ├── tests/                 # Unit tests
│   │   ├── __init__.py
│   │   ├── test_finite_field.py
│   │   ├── test_polynomial.py
│   │   ├── test_pcp.py
│   │   ├── test_qap.py
│   │   ├── test_lip.py
│   │   └── test_piop.py
│   ├── examples/              # Usage examples
│   │   ├── __init__.py
│   │   └── demo_all.py
│   └── benchmarks/            # Performance benchmarks
│       ├── __init__.py
│       └── benchmark.py
├── setup.py                   # Package setup
├── requirements.txt           # Dependencies
├── .gitignore
├── LICENSE
└── README.md
```

## Usage Examples

### Example 1: Finite Field Arithmetic

```python
from snarks.core.finite_field import FiniteField

# Create field elements in F_7
a = FiniteField(5, 7)
b = FiniteField(3, 7)

# Arithmetic operations
c = a + b          # Addition: 8 mod 7 = 1
d = a * b          # Multiplication: 15 mod 7 = 1
e = a / b          # Division: 5 * inv(3) mod 7
f = a ** 2         # Exponentiation: 25 mod 7 = 4

print(f"Addition: {c}")           # Output: 1 (mod 7)
print(f"Multiplication: {d}")     # Output: 1 (mod 7)
```

### Example 2: Polynomial Operations

```python
from snarks.core.polynomial import Polynomial
from snarks.core.finite_field import FiniteField

# Create polynomial p(x) = 1 + 2x + 3x^2 in F_7
coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
p = Polynomial(coeffs)

# Evaluate at x = 2
x = FiniteField(2, 7)
result = p.evaluate(x)  # 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17 mod 7 = 3

# Polynomial arithmetic
q = Polynomial([FiniteField(1, 7), FiniteField(1, 7)])  # q(x) = 1 + x
r = p + q          # Add polynomials
s = p * q          # Multiply polynomials
```

### Example 3: PCP Proof

```python
from snarks.proofs.pcp import PCP

# Setup
setup = PCP.setup(modulus=97, constraint_degree=2)

# Create a proof that we know values summing to 12
witness = [3, 4, 5]   # Secret: three values
statement = [12]       # Public: their sum is 12

# Generate proof
proof = PCP.prove(setup, witness, statement)

# Verify proof
is_valid = PCP.verify(setup, proof, statement)
print(f"Proof valid: {is_valid}")
```

### Example 4: QAP Proof

```python
from snarks.proofs.qap import QAP

# Setup for circuit: x * y = z
setup = QAP.setup(modulus=97)

# Prove knowledge of x, y such that x * y = z
witness = [1, 3, 4, 12]    # [constant, x, y, z] where 3*4=12
proof = QAP.prove(setup, witness)

# Verify with public inputs
public_inputs = [1, 12]     # constant and result are public
is_valid = QAP.verify(setup, proof, public_inputs)
print(f"Proof valid: {is_valid}")
```

### Example 5: LIP Interactive Proof

```python
from snarks.proofs.lip import LIP

# Setup
setup = LIP.setup(modulus=97, num_variables=3, num_rounds=2)

# Interactive protocol
witness = [3, 4, 5]
statement = [12]
proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
print(f"Interactive proof valid: {is_valid}")
```

### Example 6: PIOP with Polynomial Oracles

```python
from snarks.proofs.piop import PIOP

# Setup
setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)

# Create proof with polynomial oracles
witness = [3, 4, 5]
statement = [60]      # Product = 60
proof, is_valid = PIOP.interactive_prove_verify(setup, witness, statement)

print(f"PIOP proof valid: {is_valid}")
print(f"Number of oracles: {len(proof.oracles)}")
```

## Running Tests

The project uses `pytest` for testing. All tests are located in the `snarks/tests/` directory.

### Run All Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=snarks --cov-report=html
```

### Run Specific Test Files

```bash
# Test finite field operations
pytest snarks/tests/test_finite_field.py

# Test polynomial operations
pytest snarks/tests/test_polynomial.py

# Test specific proof system
pytest snarks/tests/test_qap.py
```

### Test Coverage

The test suite includes:
- ✅ Core module tests (finite fields, polynomials)
- ✅ Proof system tests (PCP, QAP, LIP, PIOP)
- ✅ Edge cases and error handling
- ✅ Integration tests

Expected output:
```
============================= test session starts ==============================
collected 50+ items

snarks/tests/test_finite_field.py ................                      [ 32%]
snarks/tests/test_polynomial.py ..................                      [ 68%]
snarks/tests/test_pcp.py ......                                         [ 80%]
snarks/tests/test_qap.py ......                                         [ 88%]
snarks/tests/test_lip.py ......                                         [ 94%]
snarks/tests/test_piop.py ......                                        [100%]

============================== 50+ passed in 2.50s ==============================
```

## Benchmarks

### Running Benchmarks

```bash
# Run all benchmarks
python -m snarks.benchmarks.benchmark

# Run with custom iterations
python -c "from snarks.benchmarks.benchmark import run_all_benchmarks, print_summary; results = run_all_benchmarks(iterations=1000); print_summary(results)"
```

### Expected Performance

Benchmark results (100 iterations, modulus=97):

```
======================================================================
Benchmark Summary (Average per iteration)
======================================================================
System     Setup (ms)      Prove (ms)      Verify (ms)    
----------------------------------------------------------------------
PCP        0.050          0.080           0.040          
QAP        0.060          0.120           0.100          
LIP        0.045          0.150           0.030          
PIOP       0.070          0.200           0.180          
======================================================================
```

**Note**: These are approximate values on a typical modern CPU. Actual performance will vary based on hardware and system load.

### What is Measured

- **Setup Time**: Time to generate system parameters
- **Prove Time**: Time to create a proof
- **Verify Time**: Time to verify a proof

## API Documentation

### Core Modules

#### FiniteField

```python
class FiniteField:
    """Finite field element in F_p."""
    
    def __init__(self, value: int, modulus: int)
    def __add__(self, other: 'FiniteField') -> 'FiniteField'
    def __sub__(self, other: 'FiniteField') -> 'FiniteField'
    def __mul__(self, other: Union['FiniteField', int]) -> 'FiniteField'
    def __truediv__(self, other: 'FiniteField') -> 'FiniteField'
    def __pow__(self, exponent: int) -> 'FiniteField'
    def inverse(self) -> 'FiniteField'
```

#### Polynomial

```python
class Polynomial:
    """Polynomial with finite field coefficients."""
    
    def __init__(self, coefficients: List[FiniteField])
    def degree(self) -> int
    def evaluate(self, x: FiniteField) -> FiniteField
    def __add__(self, other: 'Polynomial') -> 'Polynomial'
    def __mul__(self, other: Union['Polynomial', FiniteField, int]) -> 'Polynomial'
    
    @classmethod
    def zero(cls, modulus: int) -> 'Polynomial'
    @classmethod
    def constant(cls, value: int, modulus: int) -> 'Polynomial'
    @classmethod
    def monomial(cls, degree: int, coefficient: int, modulus: int) -> 'Polynomial'
```

### Proof Systems

All proof systems follow a consistent interface:

```python
class ProofSystem:
    @staticmethod
    def setup(...) -> Setup
    
    @staticmethod
    def prove(setup: Setup, witness: List[int], ...) -> Proof
    
    @staticmethod
    def verify(setup: Setup, proof: Proof, ...) -> bool
```

See individual module docstrings for detailed API documentation.

## Contributing

Contributions are welcome! This is an educational project, and improvements to clarity, correctness, and pedagogy are especially appreciated.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add type hints to all functions
- Write comprehensive docstrings
- Include unit tests for new code
- Update README for significant changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This implementation is inspired by:
- Academic papers on PCP, QAP, and PIOP
- Modern zk-SNARK constructions (Groth16, PLONK, Marlin)
- Educational resources on zero-knowledge proofs

## References

- **PCP Theorem**: Arora & Safra (1998), "Probabilistic Checking of Proofs"
- **QAP**: Gennaro et al. (2013), "Quadratic Span Programs and Succinct NIZKs"
- **PIOP**: Chiesa et al. (2019), "Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS"
- **zkSNARKs**: Ben-Sasson et al., "Succinct Non-Interactive Zero Knowledge"

## Contact

Marco Simoncini - [@Aslan-256](https://github.com/Aslan-256)

Project Link: [https://github.com/Aslan-256/SNARKs](https://github.com/Aslan-256/SNARKs)

---

**Disclaimer**: This is an educational implementation for learning purposes. Do not use in production systems requiring cryptographic security.
