"""
Demonstration of the new circuit-based QAP architecture.

This matches the exact API requested in the refactor specification.
"""

from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

print("=" * 70)
print("zkSNARK Demo: Circuit-Based QAP with Trusted Setup")
print("=" * 70)
print()

# 1. Define Circuit: out = (in1 + in2) * in3
print("Step 1: Define Circuit")
print("-" * 70)
circuit = ArithmeticCircuit()
i1, i2, i3 = circuit.add_inputs(3)
add_gate = circuit.add(i1, i2)
out = circuit.mul(add_gate, i3)
circuit.set_output(out)

print(f"Circuit defined: out = (in1 + in2) * in3")
print(f"Circuit info: {circuit}")
print(f"  - Total gates: {circuit.get_num_gates()}")
print(f"  - Multiplication gates: {circuit.get_num_multiplication_gates()}")
print(f"  - Inputs: {len(circuit.inputs)}")
print(f"  - Outputs: {len(circuit.outputs)}")
print()

# 2. Setup
print("Step 2: Trusted Setup (Generate CRS)")
print("-" * 70)
qap = QAP(circuit)
pk, vk = qap.setup()
print(f"Proving Key (pk): {pk}")
print(f"Verification Key (vk): {vk}")
print("  ⚠️  In production: secret τ must be destroyed!")
print()

# 3. Prove
print("Step 3: Generate Proof")
print("-" * 70)
print("Prover knows: in1=2, in2=3, in3=4")
print("Public statement: out=20")
print()

proof = qap.prove(
    pk,
    public_inputs={out: 20},         # Public: the result
    witness={i1: 2, i2: 3, i3: 4}   # Private: secret inputs
)

print(f"Proof generated: {proof}")
print(f"  - Quotient polynomial H(x) degree: {proof.H_poly.degree()}")
print(f"  - Witness size: {len(proof.witness)} field elements")
print()

# 4. Verify
print("Step 4: Verify Proof")
print("-" * 70)
print("Verifier only knows: out=20 (doesn't know in1, in2, in3)")
print()

is_valid = qap.verify(vk, public_inputs={out: 20}, proof=proof)
print(f"✅ Proof valid: {is_valid}")
print()

# Test with wrong public input (should fail)
print("Test: Verify with wrong public input...")
is_valid_wrong = qap.verify(vk, public_inputs={out: 999}, proof=proof)
print(f"❌ Proof valid (wrong input): {is_valid_wrong}")
print()

print("=" * 70)
print("Demo Complete!")
print("=" * 70)
print()
print("Key Concepts Demonstrated:")
print("  1. Arithmetic Circuit representation (DAG with gates)")
print("  2. Trusted Setup (pk, vk generation with secret τ)")
print("  3. Zero-Knowledge Proof (prover knows witness, verifier doesn't)")
print("  4. Succinct Verification (polynomial divisibility check)")
print()
print("Pipeline: Circuit → R1CS → QAP → Setup → Prove → Verify")
