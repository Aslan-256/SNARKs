# Quick Start Guide

This guide will help you get started with the SNARKs library in just a few minutes.

## Installation

```bash
# Clone the repository
git clone https://github.com/Aslan-256/SNARKs.git
cd SNARKs

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Your First Proof

Let's create a simple zero-knowledge proof using QAP (Quadratic Arithmetic Programs):

```python
from snarks.proofs.qap import QAP

# Step 1: Setup the system
setup = QAP.setup(modulus=97)

# Step 2: Define your witness (what you want to prove you know)
# In this case: we know x=3 and y=4 such that x*y=12
witness = [1, 3, 4, 12]  # [constant, x, y, result]

# Step 3: Generate the proof
proof = QAP.prove(setup, witness)

# Step 4: Verify the proof (verifier only sees public inputs)
public_inputs = [1, 12]  # constant and result are public
is_valid = QAP.verify(setup, proof, public_inputs)

print(f"Proof valid: {is_valid}")  # Output: True
```

## Try All Systems

Run the complete demo to see all four proof systems in action:

```bash
python -m snarks.examples.demo_all
```

## Run Tests

Verify everything works correctly:

```bash
pytest snarks/tests/ -v
```

## Next Steps

1. **Explore the Examples**: Check out `snarks/examples/demo_all.py` for detailed examples
2. **Read the Theory**: See the main README.md for theoretical background
3. **Run Benchmarks**: `python -m snarks.benchmarks.benchmark`
4. **Study the Code**: Start with `snarks/core/finite_field.py` to understand the basics

## Common Use Cases

### Working with Finite Fields

```python
from snarks.core.finite_field import FiniteField

a = FiniteField(5, 7)  # 5 in field F_7
b = FiniteField(3, 7)  # 3 in field F_7

c = a + b  # Addition
d = a * b  # Multiplication
e = a / b  # Division (uses multiplicative inverse)
```

### Working with Polynomials

```python
from snarks.core.polynomial import Polynomial
from snarks.core.finite_field import FiniteField

# Create polynomial p(x) = 1 + 2x + 3x^2 in F_7
coeffs = [FiniteField(1, 7), FiniteField(2, 7), FiniteField(3, 7)]
p = Polynomial(coeffs)

# Evaluate at x=2
result = p.evaluate(FiniteField(2, 7))
print(f"p(2) = {result}")
```

### Interactive Proofs with LIP

```python
from snarks.proofs.lip import LIP

setup = LIP.setup(modulus=97, num_variables=3, num_rounds=2)
witness = [3, 4, 5]  # Secret values
statement = [12]     # Public: sum = 12

# Run interactive protocol
proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
print(f"Proof valid: {is_valid}")
```

### Polynomial Oracles with PIOP

```python
from snarks.proofs.piop import PIOP

setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
witness = [3, 4, 5]
statement = [60]  # Product = 60

proof, is_valid = PIOP.interactive_prove_verify(setup, witness, statement)
print(f"Number of polynomial oracles: {len(proof.oracles)}")
print(f"Proof valid: {is_valid}")
```

## Need Help?

- **Documentation**: See README.md for comprehensive documentation
- **Issues**: Report bugs on GitHub Issues
- **Examples**: Check `snarks/examples/` for more examples
- **Tests**: Look at `snarks/tests/` to understand expected behavior

Happy proving! 🔐
