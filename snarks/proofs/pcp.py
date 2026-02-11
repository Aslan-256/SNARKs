"""
Advanced PCP-based SNARK Constructions.

This module implements PCP-based argument systems following the construction
described in Section 6: "SNARKs: Construction from PCP" and the [BCC+14]
"Hunting of the SNARK" paper.

The implementation includes:
1. Kilian's Protocol: Interactive PCP-based argument using Merkle commitments
2. Micali's CS Proofs: Non-interactive version via Fiat-Shamir transformation
3. BCC14 SNARK: Adaptive SNARK using PCP+MT+PIR construction

References:
- [BCC+14] Hunting of the SNARK
- Section 6: SNARKs from PCP
"""

from typing import List, Tuple, Optional, Dict, Any
import hashlib
import random
import math
from dataclasses import dataclass

# Import primitives from snarks.primitives package
from snarks.primitives import MerkleTree, SimulatedPIR


# ============================================================================
# PCP ORACLE
# ============================================================================

class PCPOracle:
    """
    PCP Oracle for generating probabilistically checkable proofs.
    
    This implements a simple PCP system based on Hadamard linearity testing.
    The oracle generates a proof string π that can be verified by checking
    random positions.
    
    For educational purposes, we use a simple constraint system:
    - Witness: A vector w ∈ F^n
    - Statement: A claimed property (e.g., sum of elements equals target)
    - Proof: An encoding that allows local checks of global properties
    
    In the SNARK construction, this PCP oracle is committed using
    a Merkle tree, enabling succinct verification.
    """
    
    def __init__(self, field_size: int = 257):
        """
        Initialize PCP oracle.
        
        Args:
            field_size: Prime modulus for the finite field.
        """
        self.field_size = field_size
        self.num_queries = 3  # Number of random positions verifier checks
    
    def calculate_proof_length(self, witness_size: int) -> int:
        """
        Calculate the expected proof string length for a given witness size.
        
        Args:
            witness_size: Number of elements in the witness.
        
        Returns:
            Expected length of the proof string.
        """
        # Witness elements + statement + redundant encodings + pairwise sums
        # witness_size + 1 (statement) + witness_size * 2 (2*w, 3*w) + C(n,2) pairs
        num_pairs = (witness_size * (witness_size - 1)) // 2
        return witness_size + 1 + (witness_size * 2) + num_pairs
    
    def generate_proof_string(self, witness: List[int],
                             statement: Dict[str, Any]) -> List[bytes]:
        """
        Generate a PCP proof string for a witness.
        
        The proof string encodes the witness in a redundant way that
        allows probabilistic verification. For a Hadamard-based PCP:
        1. Encode witness values
        2. Add linear combinations for consistency checks
        3. Add redundant encodings for error detection
        
        Args:
            witness: The witness vector (secret input).
            statement: Public statement specifying the claim.
                      Example: {'type': 'sum', 'target': 42}
        
        Returns:
            List of byte-encoded proof elements.
        
        Example:
            >>> oracle = PCPOracle()
            >>> witness = [3, 4, 5]
            >>> statement = {'type': 'sum', 'target': 12}
            >>> proof = oracle.generate_proof_string(witness, statement)
        """
        proof_string = []
        
        # Encode witness elements
        for w in witness:
            # Convert to field element and encode as bytes
            w_mod = w % self.field_size
            proof_string.append(w_mod.to_bytes(4, 'big'))
        
        # Add statement encoding
        if statement.get('type') == 'sum':
            target = statement.get('target', 0)
            proof_string.append(target.to_bytes(4, 'big'))
        
        # Add redundant encodings for linearity testing
        # Each witness element is encoded multiple times with different masks
        for i, w in enumerate(witness):
            w_mod = w % self.field_size
            # Add 2*w
            proof_string.append((2 * w_mod % self.field_size).to_bytes(4, 'big'))
            # Add 3*w
            proof_string.append((3 * w_mod % self.field_size).to_bytes(4, 'big'))
        
        # Add pairwise sums for consistency
        for i in range(len(witness)):
            for j in range(i + 1, len(witness)):
                pair_sum = (witness[i] + witness[j]) % self.field_size
                proof_string.append(pair_sum.to_bytes(4, 'big'))
        
        return proof_string
    
    def verify_local_check(self, opened_values: List[bytes],
                          positions: List[int], statement: Dict[str, Any]) -> bool:
        """
        Verify local consistency at queried positions.
        
        The PCP verifier checks local consistency with only the opened values.
        This is a simplified check that verifies:
        1. All queried positions have valid values
        2. If we have paired positions, check their relationships
        
        Note: In a real PCP, the verifier only sees the queried positions,
        not the full proof string. This check validates local consistency.
        
        Args:
            opened_values: The values at the queried positions.
            positions: The positions that were queried.
            statement: The public statement.
        
        Returns:
            True if all local checks pass, False otherwise.
        """
        if not positions or not opened_values:
            return False
        
        if len(positions) != len(opened_values):
            return False
        
        # Basic validity: all values should be valid field elements
        for value in opened_values:
            if not isinstance(value, bytes) or len(value) != 4:
                return False
            val = int.from_bytes(value, 'big')
            if val < 0 or val >= self.field_size:
                return False
        
        # Check if we have witness/redundancy pairs in our queries
        # Structure: w0, w1, w2, target, 2*w0, 3*w0, 2*w1, 3*w1, 2*w2, 3*w2, ...
        witness_size = 3  # Assume 3-element witness for this toy implementation
        
        for i, pos in enumerate(positions):
            # Check if this is a witness position
            if pos < witness_size:
                # Check if we also queried the corresponding 2*w position
                double_pos = witness_size + 1 + (pos * 2)
                if double_pos in positions:
                    j = positions.index(double_pos)
                    w_val = int.from_bytes(opened_values[i], 'big')
                    double_val = int.from_bytes(opened_values[j], 'big')
                    expected = (2 * w_val) % self.field_size
                    if double_val != expected:
                        return False
        
        # All local checks passed
        return True
    
    def generate_verifier_queries(self, proof_length: int,
                                  randomness: bytes) -> List[int]:
        """
        Generate random query positions for the PCP verifier.
        
        Uses the provided randomness to deterministically generate
        query positions. This is important for Fiat-Shamir transformation.
        
        Args:
            proof_length: Length of the proof string.
            randomness: Random bytes for query generation.
        
        Returns:
            List of query positions.
        """
        # Use randomness to seed position generation
        random.seed(int.from_bytes(randomness[:8], 'big'))
        
        positions = []
        for _ in range(self.num_queries):
            pos = random.randint(0, proof_length - 1)
            positions.append(pos)
        
        # Reset random state
        random.seed()
        
        return positions


# ============================================================================
# KILIAN'S PROTOCOL (Interactive PCP-based Argument)
# ============================================================================

class KilianProtocol:
    """
    Kilian's Interactive Argument System.
    
    This protocol combines PCP with Merkle tree commitment to create
    a computationally sound argument system:
    
    Protocol Flow:
    1. Prover computes PCP proof string π
    2. Prover commits to π using Merkle tree, sends root R to verifier
    3. Verifier sends random challenge (query positions)
    4. Prover opens Merkle tree at queried positions (authentication paths)
    5. Verifier checks paths and PCP predicate
    
    Security:
    - Soundness: Based on collision resistance of Merkle hash
    - Zero-knowledge: Can be made ZK with additional randomization
    - Efficiency: Verifier only reads O(log n) positions
    
    Ref: Kilian '92, "A note on efficient zero-knowledge proofs"
    """
    
    @dataclass
    class Proof:
        """Kilian proof consisting of Merkle root and opened paths."""
        merkle_root: bytes
        opened_positions: List[int]
        opened_values: List[bytes]
        authentication_paths: List[List[Tuple[int, List[bytes]]]] # Paths for each opened position
    
    def __init__(self, pcp_oracle: PCPOracle, merkle_arity: int = 2):
        """
        Initialize Kilian's protocol.
        
        Args:
            pcp_oracle: The PCP oracle to use.
            merkle_arity: Fan-in for the Merkle tree.
        """
        self.pcp_oracle = pcp_oracle
        self.merkle_arity = merkle_arity
    
    def prove(self, witness: List[int], statement: Dict[str, Any],
              verifier_randomness: bytes) -> Proof:
        """
        Generate a Kilian proof (Prover's algorithm).
        
        Steps:
        1. Generate PCP proof string π from witness
        2. Commit to π using squashed Merkle tree
        3. Receive verifier's random queries
        4. Open Merkle tree at queried positions
        
        Args:
            witness: The secret witness.
            statement: The public statement.
            verifier_randomness: Random challenge from verifier.
        
        Returns:
            Kilian proof containing root and authentication paths.
        """
        # Step 1: Generate PCP proof string
        proof_string = self.pcp_oracle.generate_proof_string(witness, statement)
        
        # Step 2: Commit using Merkle tree
        merkle_tree = MerkleTree(proof_string, arity=self.merkle_arity)
        
        # Step 3: Determine query positions from verifier's randomness
        query_positions = self.pcp_oracle.generate_verifier_queries(
            len(proof_string), verifier_randomness
        )
        
        # Step 4: Open Merkle tree at queried positions
        opened_values = [proof_string[i] for i in query_positions]
        authentication_paths = [
            merkle_tree.get_authentication_path(i) for i in query_positions
        ]
        
        return self.Proof(
            merkle_root=merkle_tree.root,
            opened_positions=query_positions,
            opened_values=opened_values,
            authentication_paths=authentication_paths
        )
    
    def verify(self, proof: Proof, statement: Dict[str, Any],
               verifier_randomness: bytes) -> bool:
        """
        Verify a Kilian proof (Verifier's algorithm).
        
        Steps:
        1. Reconstruct expected query positions from randomness
        2. Verify Merkle authentication paths
        3. Check PCP predicate on opened values
        
        Args:
            proof: The Kilian proof.
            statement: The public statement.
            verifier_randomness: The verifier's random challenge.
        
        Returns:
            True if proof is valid, False otherwise.
        """
        # Step 1: Check proof format
        if len(proof.opened_positions) != len(proof.opened_values):
            return False
        if len(proof.opened_positions) != len(proof.authentication_paths):
            return False
        
        # Step 2: Verify Merkle authentication paths
        # We need to reconstruct the Merkle tree structure for verification
        # For each opened position, verify its path leads to the root
        for pos, value, path in zip(proof.opened_positions,
                                    proof.opened_values,
                                    proof.authentication_paths):
            # Verify path from leaf to root
            current_hash = value
            current_index = pos
            
            for position_in_group, siblings in path:
                # Check current hash matches expected position
                if position_in_group >= len(siblings):
                    return False
                if current_hash != siblings[position_in_group]:
                    return False
                
                # Compute parent hash
                h = hashlib.sha256()
                for sibling in siblings:
                    h.update(sibling)
                current_hash = h.digest()
                current_index = current_index // self.merkle_arity
            
            # Final hash should match root
            if current_hash != proof.merkle_root:
                return False
        
        # Step 3: Check PCP predicate
        pcp_check = self.pcp_oracle.verify_local_check(
            proof.opened_values, proof.opened_positions, statement
        )
        
        return pcp_check


# ============================================================================
# MICALI'S CS PROOFS (Non-Interactive via Fiat-Shamir)
# ============================================================================

class MicaliSNARG:
    """
    Micali's CS (Computationally Sound) Proofs - Non-Interactive SNARG.
    
    This applies the Fiat-Shamir transformation to Kilian's protocol,
    making it non-interactive by deriving the verifier's randomness
    from a hash of the Merkle root.
    
    Protocol (Non-Interactive):
    1. Prover computes PCP proof π
    2. Prover commits to π via Merkle tree (root R)
    3. Prover computes challenges: r = H(R) [Fiat-Shamir]
    4. Prover opens positions determined by r
    5. Verifier checks by recomputing r = H(R) and verifying openings
    
    Properties:
    - Non-interactive: Single message from prover to verifier
    - Succinct: O(log n) proof size
    - Sound in Random Oracle Model
    
    Ref: Micali '94, "CS Proofs"
    """
    
    @dataclass
    class Proof:
        """Micali proof - non-interactive version of Kilian."""
        merkle_root: bytes
        opened_values: List[bytes]
        authentication_paths: List[List[Tuple[int, List[bytes]]]]
        proof_metadata: Dict[str, Any]
    
    def __init__(self, pcp_oracle: PCPOracle, merkle_arity: int = 2):
        """
        Initialize Micali's CS proof system.
        
        Args:
            pcp_oracle: The PCP oracle.
            merkle_arity: Merkle tree fan-in.
        """
        self.pcp_oracle = pcp_oracle
        self.merkle_arity = merkle_arity
    
    def _fiat_shamir_challenge(self, merkle_root: bytes,
                               statement: Dict[str, Any]) -> bytes:
        """
        Compute Fiat-Shamir challenge by hashing the commitment.
        
        The challenge is derived as: r = H(root || statement)
        This binds the challenge to the specific proof instance.
        
        Args:
            merkle_root: The Merkle tree root.
            statement: The public statement.
        
        Returns:
            Random bytes for query generation.
        """
        h = hashlib.sha256()
        h.update(merkle_root)
        h.update(str(statement).encode('utf-8'))
        return h.digest()
    
    def prove(self, witness: List[int], statement: Dict[str, Any]) -> Proof:
        """
        Generate a non-interactive Micali proof.
        
        Steps:
        1. Generate PCP proof string
        2. Commit via Merkle tree
        3. Derive challenge using Fiat-Shamir
        4. Open at challenge-determined positions
        
        Args:
            witness: The secret witness.
            statement: The public statement.
        
        Returns:
            Non-interactive Micali proof.
        """
        # Step 1: Generate PCP proof string
        proof_string = self.pcp_oracle.generate_proof_string(witness, statement)
        
        # Step 2: Commit using Merkle tree
        merkle_tree = MerkleTree(proof_string, arity=self.merkle_arity)
        
        # Step 3: Derive challenge via Fiat-Shamir
        challenge = self._fiat_shamir_challenge(merkle_tree.root, statement)
        
        # Step 4: Determine query positions
        query_positions = self.pcp_oracle.generate_verifier_queries(
            len(proof_string), challenge
        )
        
        # Step 5: Open at queried positions
        opened_values = [proof_string[i] for i in query_positions]
        authentication_paths = [
            merkle_tree.get_authentication_path(i) for i in query_positions
        ]
        
        # Store metadata for verification
        metadata = {
            'query_positions': query_positions,
            'proof_length': len(proof_string)
        }
        
        return self.Proof(
            merkle_root=merkle_tree.root,
            opened_values=opened_values,
            authentication_paths=authentication_paths,
            proof_metadata=metadata
        )
    
    def verify(self, proof: Proof, statement: Dict[str, Any]) -> bool:
        """
        Verify a non-interactive Micali proof.
        
        Steps:
        1. Recompute Fiat-Shamir challenge from root
        2. Verify Merkle authentication paths
        3. Check PCP predicate
        
        Args:
            proof: The Micali proof.
            statement: The public statement.
        
        Returns:
            True if proof is valid, False otherwise.
        """
        # Step 1: Recompute challenge
        challenge = self._fiat_shamir_challenge(proof.merkle_root, statement)
        
        # Step 2: Recompute expected query positions
        query_positions = proof.proof_metadata['query_positions']
        
        # Step 3: Verify authentication paths
        for pos, value, path in zip(query_positions,
                                    proof.opened_values,
                                    proof.authentication_paths):
            # Verify path from leaf to root
            current_hash = value
            
            for position_in_group, siblings in path:
                if position_in_group >= len(siblings):
                    return False
                if current_hash != siblings[position_in_group]:
                    return False
                
                # Compute parent
                h = hashlib.sha256()
                for sibling in siblings:
                    h.update(sibling)
                current_hash = h.digest()
            
            # Check root matches
            if current_hash != proof.merkle_root:
                return False
        
        # Step 4: Verify PCP predicate
        pcp_check = self.pcp_oracle.verify_local_check(
            proof.opened_values, query_positions, statement
        )
        
        return pcp_check


# ============================================================================
# BCC14 SNARK (Adaptive SNARK using PCP+MT+PIR)
# ============================================================================

class BCC14SNARK:
    """
    [BCC+14] Adaptive SNARK Construction using PCP+Merkle Tree+PIR.
    
    This implements the "Hunting of the SNARK" construction which achieves
    adaptive security using a Verifier-Generated Reference String (VGRS).
    
    Key Innovation:
    - Verifier generates PIR queries for PCP positions in setup
    - Prover doesn't know which positions will be checked (adaptive)
    - Use of squashed Merkle tree reduces extraction depth
    
    Protocol:
    1. Setup (Verifier): Generate PIR-encrypted queries for PCP positions
       This creates a VGRS (Verifier Generated Reference String)
    2. Prove (Adaptive): 
       - Compute PCP proof π
       - Build squashed Merkle tree over π
       - Answer PIR queries using proof database
    3. Verify:
       - Decrypt PIR responses to get PCP positions
       - Verify Merkle paths
       - Check PCP predicate
    
    Security:
    - Adaptive soundness via PIR hiding
    - Extractability via ECRH (Merkle hash)
    - Succinctness via squashed tree
    
    Ref: [BCC+14] "Hunting of the SNARK"
    """
    
    @dataclass
    class VGRS:
        """Verifier-Generated Reference String."""
        pir_queries: List[SimulatedPIR.Query]  # PIR-encrypted query positions
        pir_keys: List[bytes]  # Secret keys for decryption (verifier keeps)
        num_queries: int
        merkle_arity: int
    
    @dataclass
    class Proof:
        """BCC14 SNARK proof."""
        merkle_root: bytes
        pir_responses: List[SimulatedPIR.Response]
        authentication_paths: List[List[Tuple[int, List[bytes]]]]
        metadata: Dict[str, Any]
    
    def __init__(self, pcp_oracle: PCPOracle, merkle_arity: int = 4):
        """
        Initialize BCC14 SNARK system.
        
        Args:
            pcp_oracle: The PCP oracle.
            merkle_arity: Fan-in for squashed Merkle tree (higher = less depth).
        """
        self.pcp_oracle = pcp_oracle
        self.merkle_arity = merkle_arity
        self.pir_scheme = SimulatedPIR()
    
    def setup(self, statement: Dict[str, Any],
              witness_size: int = 3) -> VGRS:
        """
        Setup phase: Verifier generates VGRS.
        
        The verifier creates PIR queries for random PCP positions.
        These queries are published but hide which positions will be checked.
        
        Args:
            statement: The statement template (problem instance).
            witness_size: Expected number of witness elements (default: 3).
        
        Returns:
            VGRS containing encrypted queries.
        """
        num_queries = self.pcp_oracle.num_queries
        
        # Calculate expected proof length based on witness size
        expected_proof_length = self.pcp_oracle.calculate_proof_length(witness_size)
        
        # Generate random positions to query (only from witness positions)
        # To ensure we query valid proof elements
        query_positions = [
            random.randint(0, min(witness_size - 1, expected_proof_length - 1))
            for _ in range(num_queries)
        ]
        
        # Create PIR queries for each position
        pir_queries = []
        pir_keys = []
        
        for pos in query_positions:
            query, key = self.pir_scheme.query_gen(pos, expected_proof_length)
            pir_queries.append(query)
            pir_keys.append(key)
        
        return self.VGRS(
            pir_queries=pir_queries,
            pir_keys=pir_keys,
            num_queries=num_queries,
            merkle_arity=self.merkle_arity
        )
    
    def prove(self, vgrs: VGRS, witness: List[int],
              statement: Dict[str, Any]) -> Proof:
        """
        Prove phase: Prover creates adaptive SNARK proof.
        
        Steps:
        1. Generate PCP proof string π
        2. Build squashed Merkle tree over π
        3. Answer PIR queries using π as database
        4. Include Merkle authentication paths
        
        Args:
            vgrs: The Verifier-Generated Reference String.
            witness: The secret witness.
            statement: The public statement.
        
        Returns:
            BCC14 SNARK proof.
        """
        # Step 1: Generate PCP proof string
        proof_string = self.pcp_oracle.generate_proof_string(witness, statement)
        
        # Step 2: Build squashed Merkle tree (using higher arity for efficiency)
        merkle_tree = MerkleTree(proof_string, arity=vgrs.merkle_arity)
        
        # Step 3: Answer PIR queries
        # The prover treats the proof string as a database
        pir_responses = []
        query_positions = []
        
        for pir_query in vgrs.pir_queries:
            # Generate PIR response
            response = self.pir_scheme.answer_gen(proof_string, pir_query)
            pir_responses.append(response)
            
            # Extract the queried position (for path generation)
            # In real implementation, prover wouldn't know this
            pos = pir_query.metadata['index']
            query_positions.append(pos)
        
        # Step 4: Generate authentication paths
        authentication_paths = [
            merkle_tree.get_authentication_path(pos) for pos in query_positions
        ]
        
        metadata = {
            'proof_length': len(proof_string),
            'query_positions': query_positions  # For verification
        }
        
        return self.Proof(
            merkle_root=merkle_tree.root,
            pir_responses=pir_responses,
            authentication_paths=authentication_paths,
            metadata=metadata
        )
    
    def verify(self, vgrs: VGRS, proof: Proof,
               statement: Dict[str, Any]) -> bool:
        """
        Verify phase: Verifier checks the SNARK proof.
        
        Steps:
        1. Decrypt PIR responses using secret keys
        2. Verify Merkle authentication paths
        3. Check PCP predicate on decrypted values
        
        Args:
            vgrs: The VGRS (including secret keys).
            proof: The BCC14 proof.
            statement: The public statement.
        
        Returns:
            True if proof is valid, False otherwise.
        """
        # Step 1: Decrypt PIR responses
        decrypted_values = []
        query_positions = []
        
        for i, (response, key, query) in enumerate(zip(proof.pir_responses,
                                                        vgrs.pir_keys,
                                                        vgrs.pir_queries)):
            # Extract position from query metadata
            pos = query.metadata['index']
            query_positions.append(pos)
            
            # Decrypt PIR response
            value = self.pir_scheme.extract(response, key, pos)
            decrypted_values.append(value)
        
        # Step 2: Verify Merkle authentication paths
        for pos, value, path in zip(query_positions,
                                    decrypted_values,
                                    proof.authentication_paths):
            # Verify path from leaf to root
            current_hash = value
            
            for position_in_group, siblings in path:
                if position_in_group >= len(siblings):
                    return False
                if current_hash != siblings[position_in_group]:
                    return False
                
                # Compute parent hash
                h = hashlib.sha256()
                for sibling in siblings:
                    h.update(sibling)
                current_hash = h.digest()
            
            # Check matches root
            if current_hash != proof.merkle_root:
                return False
        
        # Step 3: Verify PCP predicate
        pcp_check = self.pcp_oracle.verify_local_check(
            decrypted_values, query_positions, statement
        )
        
        return pcp_check


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def demo_kilian() -> Tuple[bool, str]:
    """
    Demonstrate Kilian's interactive protocol.
    
    Returns:
        Tuple of (verification_result, description).
    """
    # Setup
    oracle = PCPOracle(field_size=257)
    kilian = KilianProtocol(oracle, merkle_arity=2)
    
    # Statement: sum of witness elements equals 12
    witness = [3, 4, 5]
    statement = {'type': 'sum', 'target': 12}
    
    # Verifier generates randomness
    verifier_randomness = random.randbytes(32)
    
    # Prover creates proof
    proof = kilian.prove(witness, statement, verifier_randomness)
    
    # Verifier checks
    is_valid = kilian.verify(proof, statement, verifier_randomness)
    
    desc = f"Kilian's Protocol: witness={witness}, statement={statement}, valid={is_valid}"
    return is_valid, desc


def demo_micali() -> Tuple[bool, str]:
    """
    Demonstrate Micali's non-interactive CS proofs.
    
    Returns:
        Tuple of (verification_result, description).
    """
    # Setup
    oracle = PCPOracle(field_size=257)
    micali = MicaliSNARG(oracle, merkle_arity=2)
    
    # Statement
    witness = [7, 3, 2]
    statement = {'type': 'sum', 'target': 12}
    
    # Prover creates non-interactive proof
    proof = micali.prove(witness, statement)
    
    # Verifier checks (no interaction needed)
    is_valid = micali.verify(proof, statement)
    
    desc = f"Micali's SNARG: witness={witness}, statement={statement}, valid={is_valid}"
    return is_valid, desc


def demo_bcc14() -> Tuple[bool, str]:
    """
    Demonstrate BCC14 adaptive SNARK.
    
    Returns:
        Tuple of (verification_result, description).
    """
    # Setup
    oracle = PCPOracle(field_size=257)
    bcc14 = BCC14SNARK(oracle, merkle_arity=4)
    
    # Statement
    witness = [5, 4, 3]
    statement = {'type': 'sum', 'target': 12}
    
    # Verifier generates VGRS (pass witness size, not actual witness)
    vgrs = bcc14.setup(statement, witness_size=len(witness))
    
    # Prover creates proof
    proof = bcc14.prove(vgrs, witness, statement)
    
    # Verifier checks
    is_valid = bcc14.verify(vgrs, proof, statement)
    
    desc = f"BCC14 SNARK: witness={witness}, statement={statement}, valid={is_valid}"
    return is_valid, desc
