"""Verify the Getting Started example from README works"""

from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

print("Testing Getting Started Example from README")
print("=" * 60)

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

# Initialize QAP from circuit
qap = QAP(circuit)

# Perform trusted setup
pk, vk = qap.setup()
print("✓ Setup complete")

# Prover knows: x = 2, Public statement: result = 6
proof = qap.prove(
    pk,
    public_inputs={result: 6},  # Public: the result is 6
    witness={x: 2}               # Private: secret input x=2
)
print("✓ Proof generated")

# Verify
is_valid = qap.verify(
    vk,
    public_inputs={result: 6},
    proof=proof
)

print(f"✓ Proof valid: {is_valid}")
assert is_valid, "Proof should be valid!"

print("\n" + "=" * 60)
print("Getting Started example works perfectly! ✅")
