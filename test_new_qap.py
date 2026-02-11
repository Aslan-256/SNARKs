"""
Test script for the new circuit-based QAP implementation.

This tests the complete zkSNARK pipeline:
    Circuit → R1CS → QAP → Setup → Prove → Verify
"""

from snarks.core.circuit import ArithmeticCircuit
from snarks.proofs.qap import QAP

def test_simple_multiplication():
    """Test: z = x * y"""
    print("=" * 60)
    print("Test 1: Simple Multiplication (z = x * y)")
    print("=" * 60)
    
    # Define circuit
    circuit = ArithmeticCircuit(modulus=97)
    x = circuit.add_input(is_public=False, name="x")
    y = circuit.add_input(is_public=False, name="y")
    z = circuit.mul(x, y, name="z")
    circuit.set_output(z)
    
    print(f"Circuit: {circuit}")
    print(f"Inputs: {len(circuit.inputs)}")
    print(f"Outputs: {len(circuit.outputs)}")
    
    # Setup
    qap = QAP(circuit)
    pk, vk = qap.setup()
    print(f"Setup complete: {pk}, {vk}")
    
    # Prove
    proof = qap.prove(pk, public_inputs={z: 12}, witness={x: 3, y: 4})
    print(f"Proof generated: {proof}")
    
    # Verify
    is_valid = qap.verify(vk, public_inputs={z: 12}, proof=proof)
    print(f"Proof valid: {is_valid}")
    assert is_valid, "Proof should be valid!"
    
    print("✓ Test 1 passed!\n")

def test_addition_and_multiplication():
    """Test: out = (x + y) * z"""
    print("=" * 60)
    print("Test 2: Addition and Multiplication (out = (x + y) * z)")
    print("=" * 60)
    
    # Define circuit
    circuit = ArithmeticCircuit(modulus=97)
    x, y, z = circuit.add_inputs(3, is_public=False)
    sum_xy = circuit.add(x, y, name="x_plus_y")
    out = circuit.mul(sum_xy, z, name="output")
    circuit.set_output(out)
    
    print(f"Circuit: {circuit}")
    
    # Setup
    qap = QAP(circuit)
    pk, vk = qap.setup()
    print(f"Setup complete")
    
    # Prove: (2 + 3) * 4 = 20
    proof = qap.prove(pk, {out: 20}, {x: 2, y: 3, z: 4})
    print(f"Proof generated for (2+3)*4=20")
    
    # Verify
    is_valid = qap.verify(vk, {out: 20}, proof)
    print(f"Proof valid: {is_valid}")
    assert is_valid, "Proof should be valid!"
    
    print("✓ Test 2 passed!\n")

def test_quadratic():
    """Test: x^2"""
    print("=" * 60)
    print("Test 3: Quadratic (y = x^2)")
    print("=" * 60)
    
    # Define circuit
    circuit = ArithmeticCircuit(modulus=97)
    x = circuit.add_input(is_public=False, name="x")
    y = circuit.mul(x, x, name="x_squared")
    circuit.set_output(y)
    
    print(f"Circuit: {circuit}")
    
    # Setup
    qap = QAP(circuit)
    pk, vk = qap.setup()
    print(f"Setup complete")
    
    # Prove: 5^2 = 25
    proof = qap.prove(pk, {y: 25}, {x: 5})
    print(f"Proof generated for 5^2=25")
    
    # Verify
    is_valid = qap.verify(vk, {y: 25}, proof)
    print(f"Proof valid: {is_valid}")
    assert is_valid, "Proof should be valid!"
    
    print("✓ Test 3 passed!\n")

def test_circuit_evaluation():
    """Test circuit evaluation"""
    print("=" * 60)
    print("Test 4: Circuit Evaluation")
    print("=" * 60)
    
    circuit = ArithmeticCircuit(modulus=97)
    a, b, c = circuit.add_inputs(3, is_public=False)
    
    # Build: out = (a + b) * c + 5
    sum_ab = circuit.add(a, b)
    mul_abc = circuit.mul(sum_ab, c)
    out = circuit.add_const(mul_abc, 5)
    circuit.set_output(out)
    
    # Evaluate
    input_values = {a: 2, b: 3, c: 4}
    wire_values = circuit.evaluate(input_values)
    
    result = wire_values[out].value
    expected = (2 + 3) * 4 + 5  # 25
    print(f"Computed: {result}, Expected: {expected}")
    assert result == expected, f"Expected {expected}, got {result}"
    
    # Check satisfiability
    is_sat = circuit.is_satisfied(input_values)
    print(f"Circuit satisfied: {is_sat}")
    assert is_sat, "Circuit should be satisfied"
    
    print("✓ Test 4 passed!\n")

def test_r1cs_conversion():
    """Test R1CS conversion"""
    print("=" * 60)
    print("Test 5: R1CS Conversion")
    print("=" * 60)
    
    from snarks.core.arithmetization import Arithmetization
    
    # Create simple circuit
    circuit = ArithmeticCircuit(modulus=97)
    x, y = circuit.add_inputs(2, is_public=False)
    z = circuit.mul(x, y)
    circuit.set_output(z)
    
    # Convert to R1CS
    r1cs = Arithmetization.circuit_to_r1cs(circuit)
    print(f"R1CS: {r1cs}")
    print(f"Constraints: {r1cs.num_constraints}")
    print(f"Variables: {r1cs.num_variables}")
    
    # Test witness
    # Witness order: [ONE, x, y, z]
    witness_values = [1, 3, 4, 12]
    is_sat = r1cs.is_satisfied(witness_values)
    print(f"Witness satisfies R1CS: {is_sat}")
    assert is_sat, "R1CS should be satisfied"
    
    print("✓ Test 5 passed!\n")

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("TESTING NEW CIRCUIT-BASED QAP IMPLEMENTATION")
    print("=" * 60 + "\n")
    
    try:
        test_simple_multiplication()
        test_addition_and_multiplication()
        test_quadratic()
        test_circuit_evaluation()
        test_r1cs_conversion()
        
        print("=" * 60)
        print("ALL TESTS PASSED! ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
