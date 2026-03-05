# zk-STARK - A Pedagogical Implementation in Python

A **from-scratch**, modular implementation of a **zk-STARK** (Zero-Knowledge
Scalable Transparent Argument of Knowledge) proof system in pure Python.
Built for learning - every module is richly commented to explain the
underlying mathematics.

---

## What Is a STARK?

A STARK lets a **prover** convince a **verifier** that a computation was
performed correctly, without revealing any secret inputs (zero-knowledge) and
without a trusted setup (transparency).  Key building blocks:

| Concept | Role |
|---|---|
| **Finite-field arithmetic** | All values live in F_p for a prime p. |
| **Algebraic Intermediate Representation (AIR)** | Encodes the computation as polynomial constraints over an execution trace. |
| **Low-Degree Extension (LDE)** | Evaluates the trace polynomial on a much larger domain, creating Reed-Solomon-like redundancy. |
| **Merkle commitment** | Binds the prover to a vector of evaluations via a single hash (the root). |
| **FRI protocol** | Proves that a committed function is close to a low-degree polynomial (the core soundness argument). |
| **Fiat-Shamir transform** | Makes the interactive protocol non-interactive by deriving challenges from a running transcript hash. |

---

## Project Structure

```
snarks/
├── __init__.py        # Package exports
├── field.py           # Prime-field arithmetic (BaseField ABC + FieldElement)
├── polynomial.py      # Polynomial ops, Lagrange interpolation, NTT/INTT
├── merkle.py          # Merkle-tree commitment (BaseHash ABC + SHA-256)
├── channel.py         # Fiat-Shamir non-interactive channel
├── air.py             # AIR base class + FibonacciAIR
├── fri.py             # FRI commit / query / verify
└── stark.py           # StarkProver & StarkVerifier orchestration
tests/
└── test_stark.py      # Full pytest suite (29 tests) + standalone runner
pyproject.toml         # Project metadata
```

### Module Overview

#### `field.py` - Finite-Field Arithmetic

Defines an abstract `BaseField` interface and a concrete `FieldElement` class
over the prime **p = 3 · 2³⁰ + 1 = 3 221 225 473**.  This prime is chosen so
that its multiplicative group has order p − 1 = 3 · 2³⁰, giving two-power
subgroups of every order 2ᵏ for k ≤ 30 - essential for efficient NTTs.

`PrimeField` is a factory that provides helpers like
`get_subgroup_generator(order)` and `get_subgroup(order)`.

#### `polynomial.py` - Polynomial Operations

- **Representation**: coefficient form (`coeffs[i]` = coefficient of x^i).
- **Evaluation**: Horner's method, O(n).
- **Interpolation**: Lagrange, O(n²).
- **NTT / INTT**: radix-2 Cooley-Tukey, O(n log n).
- **Zerofier**: Z_D(x) = ∏(x − d) for d ∈ D; for a subgroup of order n: x^n − 1.
- **Polynomial division**: long division returning `(quotient, remainder)`.

#### `merkle.py` - Merkle-Tree Commitment

Implements `BaseHash` (abstract) and `SHA256Hash` (concrete, with domain
separation between leaves and internal nodes).  `MerkleTree` builds the tree
in O(n), supports O(log n) openings, and includes a static `verify` method
for authentication-path checks.

#### `channel.py` - Fiat-Shamir Channel

Maintains a running SHA-256 state.  Every `send(data)` absorbs bytes into the
transcript; `receive_random_field_element()` and `receive_random_int(lo, hi)`
squeeze pseudo-random values.  Deterministic - identical transcripts yield
identical challenges.

#### `air.py` - Algebraic Intermediate Representation

Abstract `AIR` base class plus `FibonacciAIR` which encodes:

> a(i+2) = a(i+1) + a(i)

- **Trace**: single column of n Fibonacci values.
- **Boundary constraints**: f(ω⁰) = a₀, f(ω¹) = a₁.
- **Transition constraint**: f(ω^(i+2)) − f(ω^(i+1)) − f(ω^i) = 0 for i = 0, …, n−3.

#### `fri.py` - FRI Protocol

Implements the full **Fast Reed-Solomon IOP of Proximity**:

1. **Commit phase** - iteratively fold the polynomial evaluations using random
   challenges α_r, committing each layer with a Merkle tree.
   Folding formula: `f'(d²) = (f(d)+f(−d))/2 + α · (f(d)−f(−d))/(2d)`
2. **Query phase** - open pairs (f(d), f(−d)) at random positions through
   every layer, verifying the folding relation and Merkle paths.
3. **Final check** - the last layer reduces to a constant.

#### `stark.py` - STARK Prover & Verifier

Orchestrates the end-to-end pipeline:

**Prover** (`StarkProver.prove()`):
1. Generate the execution trace from the AIR.
2. Interpolate each column over the trace subgroup.
3. Low-Degree Extension onto a larger coset domain (blowup factor).
4. Commit the LDE via Merkle tree.
5. Build constraint quotient polynomials and combine into a single
   composition polynomial using Fiat-Shamir challenges.
6. Commit the composition LDE and run FRI to prove it is low-degree.

**Verifier** (`StarkVerifier.verify()`):
1. Rebuild the Fiat-Shamir transcript.
2. Verify the FRI proof.
3. Verify Merkle openings for trace and composition evaluations.
4. Spot-check boundary constraints at queried positions.

---

## Quick Start

### Requirements

- **Python 3.10+**
- **pytest** (for the test suite)

No external heavy cryptographic libraries are required - the implementation
uses only the Python standard library (`hashlib`, `abc`, `dataclasses`).

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd SNARKs

# (Optional) Create a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# Install in development mode
pip install -e ".[test]"
```

### Running the Tests

```bash
# Full pytest suite (29 tests)
pytest -v

# Standalone integration test
python -m tests.test_stark
```

### Usage Example

```python
from snarks import FibonacciAIR, StarkProver, StarkVerifier

# Define the computation: Fibonacci(1, 1) for 8 steps.
air = FibonacciAIR(a0=1, a1=1, num_steps=8)

# Generate a STARK proof.
prover = StarkProver(air, blowup_factor=8, num_queries=16)
proof = prover.prove()

# Verify the proof (returns True / False).
verifier = StarkVerifier(air, blowup_factor=8, num_queries=16)
assert verifier.verify(proof)
print("Proof verified!")
```

---

## Design Principles

### Modularity via ABCs

Three core interfaces are defined as Abstract Base Classes so that
implementations can be swapped without touching the rest of the stack:

| ABC | Purpose | Default implementation |
|---|---|---|
| `BaseField` | Field arithmetic | `FieldElement` (F_p, p = 3·2³⁰+1) |
| `BaseHash` | Hash function for Merkle trees | `SHA256Hash` |
| `AIR` | Algebraic constraints | `FibonacciAIR` |

### Clarity Over Speed

All algorithms favour readability:

- Schoolbook O(n²) polynomial multiplication (not NTT-based).
- Lagrange interpolation rather than optimised subgroup-NTT interpolation.
- SHA-256 hashing via the standard library.

For production use, replace with NTT-based polynomial arithmetic and an
algebraic hash (e.g., Poseidon or Rescue).

### Fiat-Shamir Soundness

The `Channel` class accumulates every prover message into a running SHA-256
digest.  Challenges are derived by squeezing the digest, ensuring the
non-interactive protocol is sound in the Random Oracle Model.

---

## Parameters & Tuning

| Parameter | Default | Effect |
|---|---|---|
| `num_steps` | 8 | Trace length (must be power of 2). Larger → more computation proved. |
| `blowup_factor` | 8 | LDE domain / trace domain ratio. Larger → higher soundness, more prover work. |
| `num_queries` | 16 | FRI query count. Larger → higher soundness, larger proof. |

The **soundness error** is approximately `(1/blowup)^num_queries`.
With the defaults (blowup=8, queries=16) this is `(1/8)^16 ≈ 2⁻⁴⁸`.

---

## How It Works - Step by Step

### 1. Trace Generation

The prover executes the computation (e.g. Fibonacci) and writes the
intermediate state values into an **execution trace** - a matrix of field
elements with one column per register and one row per time step.

### 2. Polynomial Interpolation

Each trace column is interpolated as a polynomial over a **multiplicative
subgroup** of order n (the trace length).  The polynomial `f(x)` satisfies
`f(ω^i) = trace[i]` where ω is a primitive n-th root of unity.

### 3. Low-Degree Extension (LDE)

The trace polynomial is evaluated on a **much larger** coset domain (of size
`blowup_factor × n`).  This "blows up" the data, creating redundancy
analogous to a Reed-Solomon code.  The minimum distance of this code is what
gives the STARK its soundness:  if the prover cheats on even a single trace
cell, the LDE will differ from any valid codeword in many positions.

### 4. Constraint Composition

The AIR defines **boundary constraints** (pinning specific trace values) and
**transition constraints** (relations between consecutive rows).  Each
constraint yields a **quotient polynomial** - the constraint polynomial
divided by its zerofier (a polynomial vanishing on the rows where the
constraint must hold).  If the constraint holds, the quotient is a
well-defined polynomial; otherwise the division fails.

All quotient polynomials are combined into a single **composition polynomial**
using random Fiat-Shamir challenges.

### 5. FRI - Proving Low Degree

The prover commits to the composition polynomial's LDE and then runs the
**FRI protocol** to convince the verifier that this committed function is
close to a polynomial of bounded degree.

FRI works by iteratively "folding" the polynomial: in each round, a random
challenge α splits f(x) = f_even(x²) + x · f_odd(x²) and combines them as
f'(y) = f_even(y) + α · f_odd(y).  This halves the degree.  After log₂(d)
rounds the polynomial reduces to a constant.

### 6. Verification

The verifier replays the Fiat-Shamir transcript, checks all Merkle openings,
and verifies the FRI folding relations at randomly queried positions.  If
everything checks out, the proof is accepted.

---

## Zero-Knowledge Property via Trace Padding

### The Problem: Witness Leakage

A "plain" STARK (without blinding) achieves **succinctness** and
**soundness**, but the proof transcript can leak information about the
secret execution trace (**witness**).  During the FRI query phase the
verifier learns evaluations of the trace polynomial at randomly chosen
points.  Because the trace polynomial is uniquely determined by its
evaluations on the trace subgroup (which are exactly the witness values),
a verifier performing enough queries could, in principle, recover the
trace by polynomial interpolation.

More formally, assume the execution trace has *n* rows and is interpolated
as a polynomial *f(x)* of degree < *n*.  The polynomial *f* is fully
determined by any *n* distinct evaluations.  If the number of FRI queries
*q ≥ n*, the verifier obtains enough points to reconstruct *f* — and with
it the entire witness.

### The Solution: Randomized Blinding Rows

We achieve the **zero-knowledge** property by appending **k
cryptographically random rows** to the execution trace before polynomial
interpolation.  Concretely:

1. The prover executes the computation (e.g. Fibonacci), producing an
   execution trace of **n_exec** rows.
2. The prover appends **k** field elements drawn independently and
   uniformly at random from **F_p** using a cryptographically secure
   random number generator (`secrets.randbelow`).
3. The combined trace (execution + random padding) is interpolated over a
   multiplicative subgroup of order **n = 2^m ≥ n_exec + k** (the
   smallest power of 2 that fits).

The resulting trace polynomial *f(x)* now has degree < *n*, which is
strictly larger than the original degree < *n_exec*.  The extra *k* random
evaluation points inject *k* independent random degrees of freedom into
the polynomial's coefficient vector.

### Why It Works — Information-Theoretic Argument

**Theorem.**  If **k > q** (the number of random blinding rows strictly
exceeds the number of FRI queries), then for any fixed execution trace
the conditional distribution of the verifier's view — the *q* evaluations
of *f* at the queried points — is **statistically uniform** over **F_p^q**,
regardless of the particular witness.

*Sketch of proof.*  Fix the *n_exec* execution-trace values.  The *k*
random padding values are chosen uniformly and independently over **F_p**.
The polynomial *f* is the unique interpolant of all *n* points.  Its
coefficients are an affine function of the *k* random values (the
execution values contribute a fixed offset).  Each query evaluation
*f(z_j)* is therefore an affine function of the *k* random values.
Because *q < k*, any subset of *q* such evaluations is a
lower-dimensional affine image of a *k*-dimensional uniform distribution,
and hence is itself uniformly distributed.  ∎

In practice we set **k = num_queries + 1**, giving a margin of one degree
of freedom.  Larger values increase the proof size only marginally (the
padded trace length is rounded up to the next power of 2) while
strengthening the statistical distance guarantee.

### Adjusting the Constraint System

The random padding rows do **not** satisfy the AIR's transition
constraints (they are arbitrary field elements, not Fibonacci values).
The constraint system must therefore be adjusted:

* **Transition zerofier** — The zerofier *Z_T(x)* is modified so that it
  vanishes **only** on the execution rows where the recurrence holds:

$$Z_T(x) \;=\; \frac{x^n - 1}{\displaystyle\prod_{i\,=\,n_{\text{exec}}-2}^{\,n-1}\!(x - g^i)}$$

  The excluded set contains the last two execution rows (where the
  recurrence cannot be evaluated because it looks two steps ahead) **plus**
  all padding rows.  This ensures that the quotient
  *C(x) / Z_T(x)* is a well-defined polynomial with zero remainder.

* **Boundary constraints** — These pin specific execution rows (e.g.
  *f(g^0) = a_0*, *f(g^1) = a_1*) and are unaffected by the padding
  because the boundary zerofiers *(x − g^{step})* do not involve the
  padded rows.

* **Composition polynomial** — The degree of the composition polynomial
  increases from roughly *n_exec* to roughly *n*, but the FRI degree
  bound is adjusted automatically.  The LDE domain (size
  *blowup × n*) remains much larger, so soundness is preserved.

### Usage

```python
from snarks import FibonacciAIR, StarkProver, StarkVerifier

num_queries = 16

# num_randomizers must be > num_queries for zero-knowledge.
air = FibonacciAIR(a0=1, a1=1, num_steps=8, num_randomizers=num_queries + 1)

prover = StarkProver(air, blowup_factor=8, num_queries=num_queries)
proof = prover.prove()

verifier = StarkVerifier(air, blowup_factor=8, num_queries=num_queries)
assert verifier.verify(proof)
print("zk-STARK proof verified!")
```

---

## License

MIT - see [LICENSE](LICENSE).
