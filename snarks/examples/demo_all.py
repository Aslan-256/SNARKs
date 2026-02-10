"""
Example usage of all proof systems.

This script demonstrates how to use each of the implemented proof systems:
- PCP (Probabilistically Checkable Proofs)
- QAP (Quadratic Arithmetic Programs)
- LIP (Linear Interactive Proofs)
- PIOP (Polynomial Interactive Oracle Proofs)
"""

from snarks.proofs.pcp import demo_kilian, demo_micali, demo_bcc14
from snarks.proofs.qap import QAP
from snarks.proofs.lip import LIP
from snarks.proofs.piop import PIOP


def micali_example():
    """Demonstrate Micali's SNARG usage."""
    print("\n" + "="*70)
    print("PCP (Probabilistically Checkable Proof) Example - Micali's SNARG")
    print("="*70)
    is_valid, desc = demo_micali()
    print(desc)
    return is_valid

def bcc14_example():
    """Demonstrate BCC14 SNARK usage."""
    print("\n" + "="*70)
    print("PCP (Probabilistically Checkable Proof) Example - BCC14 SNARK")
    print("="*70)
    is_valid, desc = demo_bcc14()
    print(desc)
    return is_valid

def kilian_example():
    """Demonstrate PCP usage (Kilian's protocol)."""
    print("\n" + "="*70)
    print("PCP (Probabilistically Checkable Proof) Example - Kilian's Protocol")
    print("="*70)
    is_valid, desc = demo_kilian()
    print(desc)
    return is_valid


def qap_example():
    """Demonstrate QAP usage."""
    print("\n" + "="*70)
    print("QAP (Quadratic Arithmetic Program) Example")
    print("="*70)
    
    # Setup
    print("\n1. Setup:")
    setup = QAP.setup(modulus=97, circuit_size=3)
    print(f"   Field modulus: {setup.modulus}")
    print(f"   Circuit: x * y = z")
    
    # Define witness and public inputs
    witness = [1, 3, 4, 12]    # [constant, x, y, z] where x*y=z
    public_inputs = [1, 12]     # Public: constant and result
    print(f"\n2. Witness: {witness}")
    print(f"   Checking: {witness[1]} * {witness[2]} = {witness[3]}")
    print(f"   Public inputs: {public_inputs}")
    
    # Prove
    print("\n3. Generating proof...")
    proof = QAP.prove(setup, witness)
    print(f"   Assignment size: {len(proof.assignment)}")
    print(f"   Quotient polynomial degree: {proof.H_poly.degree()}")
    
    # Verify
    print("\n4. Verifying proof...")
    is_valid = QAP.verify(setup, proof, public_inputs)
    print(f"   Proof valid: {is_valid}")
    
    return is_valid


def lip_example():
    """Demonstrate LIP usage."""
    print("\n" + "="*70)
    print("LIP (Linear Interactive Proof) Example")
    print("="*70)
    
    # Setup
    print("\n1. Setup:")
    setup = LIP.setup(modulus=97, num_variables=3, num_rounds=2)
    print(f"   Field modulus: {setup.modulus}")
    print(f"   Number of variables: {setup.num_variables}")
    print(f"   Interaction rounds: {setup.num_rounds}")
    
    # Define witness and statement
    witness = [3, 4, 5]  # Secret values
    statement = [12]     # Public statement: sum = 12
    print(f"\n2. Witness (secret): {witness}")
    print(f"   Statement (public): sum = {statement[0]}")
    
    # Interactive protocol
    print("\n3. Running interactive protocol...")
    print("   (Verifier sends challenges, Prover responds)")
    proof, is_valid = LIP.interactive_prove_verify(setup, witness, statement)
    print(f"   Number of responses: {len(proof.responses)}")
    print(f"   Commitment size: {len(proof.commitment)}")
    
    # Result
    print("\n4. Verification result:")
    print(f"   Proof valid: {is_valid}")
    
    return is_valid


def piop_example():
    """Demonstrate PIOP usage."""
    print("\n" + "="*70)
    print("PIOP (Polynomial Interactive Oracle Proof) Example")
    print("="*70)
    
    # Setup
    print("\n1. Setup:")
    setup = PIOP.setup(modulus=97, num_variables=3, poly_degree=3)
    print(f"   Field modulus: {setup.modulus}")
    print(f"   Number of variables: {setup.num_variables}")
    print(f"   Max polynomial degree: {setup.poly_degree}")
    
    # Define witness and statement
    witness = [3, 4, 5]  # Secret values
    statement = [60]     # Public statement: product = 60
    print(f"\n2. Witness (secret): {witness}")
    print(f"   Statement (public): product = {statement[0]}")
    
    # Interactive protocol with polynomial oracles
    print("\n3. Running interactive protocol with polynomial oracles...")
    print("   (Prover commits to polynomials, Verifier queries)")
    proof, is_valid = PIOP.interactive_prove_verify(setup, witness, statement)
    
    print(f"   Number of oracles: {len(proof.oracles)}")
    print(f"   Oracle names: {list(proof.oracles.keys())}")
    for name, oracle in proof.oracles.items():
        print(f"   - {name}: degree {oracle.polynomial.degree()}")
    
    # Result
    print("\n4. Verification result:")
    print(f"   Proof valid: {is_valid}")
    
    return is_valid


def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("SNARK Proof Systems - Complete Examples")
    print("="*70)
    print("\nThis demonstration shows all four implemented proof systems:")
    print("  • PCP  - Probabilistically Checkable Proofs")
    print("      • Kilian's Protocol")
    print("      • Micali's SNARG")
    print("      • BCC14 SNARK")
    print("  • QAP  - Quadratic Arithmetic Programs")
    print("  • LIP  - Linear Interactive Proofs")
    print("  • PIOP - Polynomial Interactive Oracle Proofs")
    
    results = {}
    # Run each example
    results['Kilian'] = kilian_example()
    results['Micali'] = micali_example()
    results['BCC14'] = bcc14_example()
    results['QAP'] = qap_example()
    results['LIP'] = lip_example()
    results['PIOP'] = piop_example()
    # Summary
    print("\n" + "="*70)
    print("Summary")
    print("="*70)
    for system, valid in results.items():
        status = "✓ PASSED" if valid else "✗ FAILED"
        print(f"  {system:6s} : {status}")
    all_passed = all(results.values())
    print(f"\nOverall: {'All systems working correctly!' if all_passed else 'Some systems failed.'}")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
