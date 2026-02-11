#!/usr/bin/env python3
"""
Demonstration of cryptographic primitives for zkSNARKs.

This script showcases all the newly implemented primitives:
- Merkle Trees (with authentication paths)
- Private Information Retrieval (PIR)
- Fiat-Shamir Transcripts
- KZG Polynomial Commitments
- Pedersen Vector Commitments
"""

from snarks.primitives import (
    MerkleTree,
    SimulatedPIR,
    Transcript,
    KZGCommitment,
    PedersenVectorCommitment
)


def demo_merkle_tree():
    """Demonstrate Merkle tree with authentication paths."""
    print("=" * 60)
    print("MERKLE TREE DEMONSTRATION")
    print("=" * 60)
    
    # Create data
    data = [f"transaction_{i}".encode() for i in range(8)]
    print(f"\n📦 Creating Merkle tree with {len(data)} leaves")
    
    # Create binary tree (arity=2)
    tree = MerkleTree(data, arity=2)
    print(f"✓ Tree root: {tree.root.hex()[:16]}...")
    print(f"✓ Tree depth: {len(tree.tree)} levels")
    
    # Generate authentication path for leaf 5
    leaf_idx = 5
    print(f"\n🔍 Generating authentication path for leaf {leaf_idx}")
    path = tree.get_authentication_path(leaf_idx)
    print(f"✓ Path length: {len(path)} levels")
    
    # Verify the path
    is_valid = tree.verify_authentication_path(leaf_idx, data[leaf_idx], path)
    print(f"✓ Path verification: {'VALID ✓' if is_valid else 'INVALID ✗'}")
    
    # Try to verify with wrong data
    is_valid_wrong = tree.verify_authentication_path(leaf_idx, b"wrong_data", path)
    print(f"✓ Wrong data verification: {'INVALID ✓' if not is_valid_wrong else 'VALID ✗'}")
    
    # Create squashed tree (arity=4)
    print(f"\n📦 Creating squashed tree (arity=4)")
    data16 = [f"item_{i}".encode() for i in range(16)]
    tree4 = MerkleTree(data16, arity=4)
    print(f"✓ Binary tree depth: {len(MerkleTree(data16, arity=2).tree)} levels")
    print(f"✓ Squashed tree depth: {len(tree4.tree)} levels")
    print(f"✓ Depth reduction: {len(MerkleTree(data16, arity=2).tree) - len(tree4.tree)} levels")


def demo_pir():
    """Demonstrate Private Information Retrieval."""
    print("\n" + "=" * 60)
    print("PRIVATE INFORMATION RETRIEVAL (PIR) DEMONSTRATION")
    print("=" * 60)
    
    # Create database
    database = [f"secret_record_{i}".encode() for i in range(10)]
    print(f"\n📚 Database size: {len(database)} items")
    
    # Initialize PIR
    pir = SimulatedPIR(security_parameter=128)
    
    # Client generates query for index 7 (private)
    target_index = 7
    print(f"\n🔐 Client queries index {target_index} (privately)")
    query, secret_key = pir.query_gen(target_index, len(database))
    print(f"✓ Query generated (ciphertext: {query.ciphertext.hex()[:16]}...)")
    
    # Server responds (without knowing which index)
    print(f"\n🖥️  Server generates response")
    response = pir.answer_gen(database, query)
    print(f"✓ Response size: {len(response.data)} bytes")
    
    # Client extracts answer
    result = pir.extract(response, secret_key, target_index)
    print(f"\n✅ Client extracts: {result.decode()}")
    print(f"✓ Correct: {result == database[target_index]}")
    
    # Show communication complexity
    complexity = pir.get_communication_complexity(len(database))
    print(f"\n📊 Communication complexity:")
    print(f"   Query size: {complexity['query_size']} bytes")
    print(f"   Response overhead: {complexity['response_overhead']} bytes")


def demo_fiat_shamir():
    """Demonstrate Fiat-Shamir transcript."""
    print("\n" + "=" * 60)
    print("FIAT-SHAMIR TRANSCRIPT DEMONSTRATION")
    print("=" * 60)
    
    # Create transcript
    print("\n📝 Simulating Schnorr-like proof protocol")
    prover_transcript = Transcript(protocol_label="SchnorrProof-v1.0")
    
    # Round 1: Prover commits
    commitment = 987654321
    print(f"\n1️⃣  Prover commits: {commitment}")
    prover_transcript.absorb("commitment", commitment)
    
    # Generate challenge (replaces verifier randomness)
    p = 2**255 - 19  # Curve25519 field
    challenge = prover_transcript.squeeze_field_element("challenge", p)
    print(f"2️⃣  Challenge (Fiat-Shamir): {challenge}")
    
    # Round 2: Prover responds
    response = 123456789
    print(f"3️⃣  Prover responds: {response}")
    prover_transcript.absorb("response", response)
    
    # Verifier replays transcript
    print(f"\n🔍 Verifier replays transcript:")
    verifier_transcript = Transcript(protocol_label="SchnorrProof-v1.0")
    verifier_transcript.absorb("commitment", commitment)
    verifier_challenge = verifier_transcript.squeeze_field_element("challenge", p)
    
    print(f"✓ Verifier's challenge matches: {verifier_challenge == challenge}")
    verifier_transcript.absorb("response", response)
    
    # Show determinism
    print(f"\n📊 Transcript properties:")
    print(f"   Protocol: {prover_transcript.protocol_label}")
    print(f"   Messages absorbed: {len(prover_transcript.get_history())}")
    print(f"   Deterministic: ✓ (same input → same challenges)")


def demo_kzg_commitment():
    """Demonstrate KZG polynomial commitments."""
    print("\n" + "=" * 60)
    print("KZG POLYNOMIAL COMMITMENT DEMONSTRATION")
    print("=" * 60)
    
    # Initialize KZG
    p = 101  # Small field for demo
    kzg = KZGCommitment(field_modulus=p)
    
    print(f"\n🔧 Trusted setup (field modulus: {p})")
    setup = kzg.setup(max_degree=10)
    print(f"✓ Setup complete (max degree: {setup.max_degree})")
    print(f"✓ Powers of tau generated: {len(setup.powers_of_tau_g1)}")
    
    # Commit to polynomial f(X) = 3 + 7X + 2X² + X³
    poly = [3, 7, 2, 1]
    print(f"\n📜 Polynomial: f(X) = 3 + 7X + 2X² + X³")
    commitment = kzg.commit(poly, setup)
    print(f"✓ Commitment (constant size): {commitment}")
    
    # Open at x = 5
    x = 5
    y_expected = 3 + 7*5 + 2*25 + 125  # = 3 + 35 + 50 + 125 = 213 mod 101 = 11
    y, proof = kzg.open(poly, x, setup)
    print(f"\n🔓 Opening at x = {x}")
    print(f"✓ Evaluation: f({x}) = {y}")
    print(f"✓ Expected: {y_expected % p}")
    print(f"✓ Proof (constant size): {proof}")
    
    # Verify
    is_valid = kzg.verify(commitment, x, y, proof, setup)
    print(f"\n✅ Verification: {'VALID ✓' if is_valid else 'INVALID ✗'}")
    
    # Test invalid opening
    wrong_y = (y + 1) % p
    is_valid_wrong = kzg.verify(commitment, x, wrong_y, proof, setup)
    print(f"✗  Wrong value verification: {'INVALID ✓' if not is_valid_wrong else 'VALID ✗'}")
    
    # Batch verification
    print(f"\n📦 Batch verification demo:")
    poly2 = [1, 2, 3]
    c2 = kzg.commit(poly2, setup)
    x2 = 3
    y2, p2 = kzg.open(poly2, x2, setup)
    
    batch_valid = kzg.batch_verify([commitment, c2], [x, x2], [y, y2], [proof, p2], setup)
    print(f"✓ Batch verify 2 openings: {'VALID ✓' if batch_valid else 'INVALID ✗'}")


def demo_pedersen_commitment():
    """Demonstrate Pedersen vector commitments."""
    print("\n" + "=" * 60)
    print("PEDERSEN VECTOR COMMITMENT DEMONSTRATION")
    print("=" * 60)
    
    # Initialize Pedersen
    p = 101
    pedersen = PedersenVectorCommitment()
    
    print(f"\n🔧 Setup (field modulus: {p}, vector size: 5)")
    setup = pedersen.setup(vector_size=5, field_modulus=p)
    print(f"✓ Generators created: {len(setup.generators)}")
    
    # Commit to vector
    vector = [10, 20, 30, 40, 50]
    randomness = 42
    print(f"\n📊 Vector: {vector}")
    print(f"🎲 Randomness: {randomness}")
    
    commitment = pedersen.commit(vector, setup, randomness)
    print(f"✓ Commitment: {commitment}")
    
    # Open commitment
    opening = pedersen.open(vector, commitment, randomness)
    is_valid = pedersen.verify(commitment, vector, opening, setup)
    print(f"\n✅ Verification: {'VALID ✓' if is_valid else 'INVALID ✗'}")
    
    # Test hiding property
    print(f"\n🔐 Hiding property test:")
    c1 = pedersen.commit(vector, setup, randomness=10)
    c2 = pedersen.commit(vector, setup, randomness=20)
    print(f"✓ Same vector, different randomness:")
    print(f"   Commitment 1: {c1}")
    print(f"   Commitment 2: {c2}")
    print(f"   Different: {c1 != c2} ✓ (hiding works)")


def main():
    """Run all demonstrations."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 8 + "zkSNARK CRYPTOGRAPHIC PRIMITIVES DEMO" + " " * 13 + "║")
    print("╚" + "=" * 58 + "╝")
    
    demo_merkle_tree()
    demo_pir()
    demo_fiat_shamir()
    demo_kzg_commitment()
    demo_pedersen_commitment()
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE ✓")
    print("=" * 60)
    print("\nAll primitives demonstrated successfully!")
    print("For more details, see:")
    print("  - snarks/primitives/merkle.py")
    print("  - snarks/primitives/pir.py")
    print("  - snarks/primitives/fiat_shamir.py")
    print("  - snarks/primitives/commitments.py")
    print("\n")


if __name__ == "__main__":
    main()
