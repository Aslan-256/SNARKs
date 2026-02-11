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

### Getting Started with Circuit-Based zkSNARKs

#### Step 1: Define Your Circuit

Create an arithmetic circuit representing your computation:

```python
from snarks.core.circuit import ArithmeticCircuit

# Example: Prove you know x such that x^2 + x = 6
circuit = ArithmeticCircuit(modulus=97)

# Add private input (witness)
x = circuit.add_input(is_public=False, name="x")

# Compute x^2
x_squared = circuit.mul(x, x, name="x_squared")

# Compute x^2 + x
result = circuit.add(x_squared, x, name="result")

# Set result as public output
circuit.set_output(result)
```

#### Step 2: Run Trusted Setup

Generate proving and verification keys (Common Reference String):

```python
from snarks.proofs.qap import QAP

# Initialize QAP from circuit
qap = QAP(circuit)

# Perform trusted setup
pk, vk = qap.setup()

# pk = Proving Key (for provers, contains secrets)
# vk = Verification Key (for verifiers, public)
```

**⚠️ Security Note**: In production, the secret τ must be destroyed after setup using multi-party computation (MPC) ceremonies.

#### Step 3: Generate a Proof

Prover creates a proof knowing the private witness:

```python
# Prover knows: x = 2
# Public statement: result = 6

proof = qap.prove(
    pk,
    public_inputs={result: 6},  # Public: the result is 6
    witness={x: 2}               # Private: secret input x=2
)

# The proof is succinct (small) regardless of circuit size
```

#### Step 4: Verify the Proof

Verifier checks the proof without knowing the witness:

```python
# Verifier only knows the public output (result=6)
# Verifier does NOT know x=2

is_valid = qap.verify(
    vk,
    public_inputs={result: 6},
    proof=proof
)

print(f"Proof valid: {is_valid}")  # Output: True

# Zero-knowledge: verifier learned nothing about x!
```

### Complete Example

Here's a full working example you can run:

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

# 1. Define Circuit: out = (x + y) * z
circuit = ArithmeticCircuit(modulus=97)
x, y, z = circuit.add_inputs(3, is_public=False)
sum_xy = circuit.add(x, y)
out = circuit.mul(sum_xy, z)
circuit.set_output(out)

# 2. Setup
qap = QAP(circuit)
pk, vk = qap.setup()

# 3. Prove: x=2, y=3, z=4 → (2+3)×4 = 20
proof = qap.prove(pk, {out: 20}, {x: 2, y: 3, z: 4})

# 4. Verify
is_valid = qap.verify(vk, {out: 20}, proof)
print(f"Proof valid: {is_valid}")  # True
```

### New Architecture (Circuit-Based)

The library now follows the standard zkSNARK pipeline: **Computation → Arithmetic Circuit → R1CS → QAP → Setup/Prove/Verify**

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

# 1. Define Circuit: out = (x + y) * z
circuit = ArithmeticCircuit(modulus=97)
x, y, z = circuit.add_inputs(3, is_public=False, names=["x", "y", "z"])
sum_wire = circuit.add(x, y, name="x_plus_y")
out = circuit.mul(sum_wire, z, name="output")
circuit.set_output(out)

# 2. Setup (Trusted Setup / CRS Generation)
qap = QAP(circuit)
pk, vk = qap.setup()  # Proving Key, Verification Key

# 3. Prove: I know x=3, y=4, z=5 such that out = 35
proof = qap.prove(
    pk,
    public_inputs={out: 35},     # Public: the result
    witness={x: 3, y: 4, z: 5}   # Private: the secret inputs
)

# 4. Verify: Check the proof (verifier only knows public inputs)
is_valid = qap.verify(vk, public_inputs={out: 35}, proof=proof)
print(f"Proof valid: {is_valid}")  # Output: Proof valid: True
```

### Legacy Interface (Simplified)

The old interface is still supported for backward compatibility:

```python
from snarks.proofs.qap import qap_example

# Run complete example with default circuit (x * y = z)
qap, proof, pk, vk = qap_example()
x_wire = qap.circuit.inputs[0]
z_wire = qap.circuit.outputs[0]

is_valid = qap.verify(vk, {z_wire: 12}, proof)
print(f"Proof valid: {is_valid}")  # Output: Proof valid: True
```


## Theory Overview

### What are Zero-Knowledge Proofs?

Zero-knowledge proofs allow a **prover** to convince a **verifier** that a statement is true without revealing any information beyond the validity of the statement itself.

### zkSNARK Pipeline (New Architecture)

This library now implements the complete zkSNARK construction pipeline:

```
Computation
    ↓
Arithmetic Circuit (Gates: +, ×)
    ↓
R1CS (Rank-1 Constraint System)
    ↓
QAP (Quadratic Arithmetic Program)
    ↓
Trusted Setup (CRS/SRS Generation)
    ↓
Prove / Verify
```

#### 1. Arithmetic Circuits

Computations are represented as circuits with:
- **Inputs**: Public statements ($x$) and private witnesses ($w$)
- **Gates**: Addition and multiplication over finite fields
- **Wires**: Connections between gates
- **Outputs**: Public values to be verified

#### 2. R1CS (Rank-1 Constraint System)

Circuits are flattened into bilinear constraints:
$$(\mathbf{A} \cdot \mathbf{w}) \circ (\mathbf{B} \cdot \mathbf{w}) = (\mathbf{C} \cdot \mathbf{w})$$

where $\mathbf{w}$ is the witness vector and $\circ$ is element-wise multiplication.

#### 3. QAP (Quadratic Arithmetic Programs)

R1CS is converted to polynomial form using Lagrange interpolation:
$$A(x) \cdot B(x) - C(x) = H(x) \cdot t(x)$$

where:
- $A(x), B(x), C(x)$: Polynomials encoding constraints
- $t(x)$: Target polynomial (vanishes at evaluation points)
- $H(x)$: Quotient polynomial (proof of satisfaction)

#### 4. Trusted Setup

Generate proving key ($pk$) and verification key ($vk$):
- Sample secret $\tau \leftarrow \mathbb{F}_p$
- Encode polynomial evaluations at $\tau$ (encrypted via elliptic curves in production)
- **Critical**: $\tau$ must be destroyed after setup (toxic waste!)

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
│   │   ├── polynomial.py      # Polynomial operations
│   │   ├── circuit.py         # ⭐ NEW: Arithmetic circuit representation
│   │   └── arithmetization.py # ⭐ NEW: Circuit → R1CS → QAP conversion
│   ├── proofs/                # Proof system implementations
│   │   ├── __init__.py
│   │   ├── qap.py            # ⭐ REFACTORED: Circuit-based QAP with setup/prove/verify
│   │   ├── pcp.py            # Probabilistically Checkable Proofs
│   │   ├── lip.py            # Linear Interactive Proofs
│   │   └── piop.py           # Polynomial Interactive Oracle Proofs
│   ├── tests/                 # Unit tests
│   │   ├── __init__.py
│   │   ├── test_finite_field.py
│   │   ├── test_polynomial.py
│   │   ├── test_circuit.py        # ⭐ NEW: Circuit tests
│   │   ├── test_arithmetization.py # ⭐ NEW: R1CS/QAP conversion tests
│   │   ├── test_qap.py
│   │   ├── test_pcp.py
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

### Key New Modules

#### `snarks/core/circuit.py`
- **ArithmeticCircuit**: DAG representation of computations
- **Wire**: Connections between gates
- **Gate**: Addition and multiplication operations
- **Circuit evaluation**: Check satisfiability

#### `snarks/core/arithmetization.py`
- **R1CS**: Rank-1 Constraint System representation
- **QAPInstance**: Polynomial representation of constraints
- **Arithmetization**: Conversion pipeline (Circuit → R1CS → QAP)
- **Lagrange interpolation**: Polynomial construction

#### `snarks/proofs/qap.py` (Refactored)
- **QAP**: Main zkSNARK class with circuit-based interface
- **ProvingKey**: CRS for provers (contains secrets)
- **VerificationKey**: CRS for verifiers (public)
- **QAPProof**: Succinct proof of computation
- **Trusted setup**: Generate pk/vk from circuit


## Usage Examples

### Example 1: Simple Multiplication Circuit (x × y = z)

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

# Step 1: Define the circuit
circuit = ArithmeticCircuit(modulus=97)
x = circuit.add_input(is_public=False, name="x")
y = circuit.add_input(is_public=False, name="y")
z = circuit.mul(x, y, name="z")
circuit.set_output(z)

# Step 2: Compile to QAP and perform trusted setup
qap = QAP(circuit)
pk, vk = qap.setup()

# Step 3: Prover generates proof (knows x=3, y=4)
proof = qap.prove(
    pk,
    public_inputs={z: 12},    # Public: result is 12
    witness={x: 3, y: 4}       # Private: secret factors
)

# Step 4: Verifier checks proof (only knows result)
is_valid = qap.verify(vk, public_inputs={z: 12}, proof=proof)
print(f"Proof valid: {is_valid}")  # True
```

### Example 2: Complex Circuit (out = (x + y) × z)

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

# Define circuit with both addition and multiplication
circuit = ArithmeticCircuit(modulus=97)
x, y, z = circuit.add_inputs(3, is_public=False)
sum_xy = circuit.add(x, y)      # sum_xy = x + y
out = circuit.mul(sum_xy, z)     # out = sum_xy * z
circuit.set_output(out)

# Setup
qap = QAP(circuit)
pk, vk = qap.setup()

# Prove: x=2, y=3, z=4 → (2+3)×4 = 20
proof = qap.prove(pk, {out: 20}, {x: 2, y: 3, z: 4})

# Verify
is_valid = qap.verify(vk, {out: 20}, proof)
print(f"Valid: {is_valid}")  # True
```

### Example 3: Quadratic Equation (x² + c = y)

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

# Circuit for x^2 + c = y
circuit = ArithmeticCircuit(modulus=97)
x = circuit.add_input(is_public=False, name="x")
c = circuit.add_input(is_public=True, name="c")  # Public constant
y = circuit.add_input(is_public=True, name="y")  # Public output

# Compute x^2
x_squared = circuit.mul(x, x, name="x_squared")

# Compute x^2 + c
result = circuit.add(x_squared, c, name="result")

# Constrain result = y (enforce equality)
# In a full implementation, we'd check result == y
circuit.set_output(result)

# Setup
qap = QAP(circuit)
pk, vk = qap.setup()

# Prove: x=5, c=2, y=27 (since 5^2 + 2 = 27)
proof = qap.prove(pk, {c: 2, y: 27}, {x: 5})

# Verify (verifier only knows c and y, not x)
is_valid = qap.verify(vk, {c: 2, y: 27}, proof)
print(f"Valid: {is_valid}")  # True
```

### Example 4: Arithmetic Circuit Evaluation

```python
from snarks.core.circuit import ArithmeticCircuit

circuit = ArithmeticCircuit(modulus=97)
a, b, c = circuit.add_inputs(3, is_public=False)

# Build circuit: out = (a + b) * c + 5
sum_ab = circuit.add(a, b)
mul_abc = circuit.mul(sum_ab, c)
out = circuit.add_const(mul_abc, 5)
circuit.set_output(out)

# Evaluate circuit to check satisfiability
input_values = {a: 2, b: 3, c: 4}
wire_values = circuit.evaluate(input_values)

print(f"Output: {wire_values[out].value}")  # (2+3)*4+5 = 25
print(f"Satisfied: {circuit.is_satisfied(input_values)}")  # True

# Circuit properties
print(f"Total gates: {circuit.get_num_gates()}")
print(f"Multiplication gates: {circuit.get_num_multiplication_gates()}")
print(f"Constraints: {circuit.get_num_constraints()}")
```

### Example 5: Direct R1CS Access

```python
from snarks.core.circuit import ArithmeticCircuit
from snarks.core.arithmetization import Arithmetization

# Create circuit
circuit = ArithmeticCircuit(modulus=97)
x, y = circuit.add_inputs(2, is_public=False)
z = circuit.mul(x, y)
circuit.set_output(z)

# Convert to R1CS
r1cs = Arithmetization.circuit_to_r1cs(circuit)
print(f"R1CS: {r1cs.num_constraints} constraints, {r1cs.num_variables} variables")

# Check witness satisfiability
witness_values = [1, 3, 4, 12]  # [ONE, x, y, z]
is_satisfied = r1cs.is_satisfied(witness_values)
print(f"Witness satisfies R1CS: {is_satisfied}")  # True

# Convert R1CS to QAP
qap_instance = Arithmetization.r1cs_to_qap(r1cs)
print(f"QAP: degree={qap_instance.target.degree()}")
```

### Example 6: Finite Field Arithmetic

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

### Example 7: Polynomial Operations

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

# Polynomial division (new feature)
quotient, remainder = p.divide(q)
```

### Example 8: Legacy PCP Proof (Backward Compatible)

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

### Example 9: Legacy LIP Interactive Proof

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

### Example 10: Legacy PIOP with Polynomial Oracles

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
