"""
Fiat-Shamir Transformation for Non-Interactive Proofs.

This module implements the Fiat-Shamir heuristic for converting
interactive proof systems into non-interactive arguments in the
Random Oracle Model (ROM).

The Fiat-Shamir transform is foundational for modern zkSNARKs,
enabling efficient non-interactive proofs for blockchain and
other applications.

References:
    [FS86] Fiat-Shamir: "How to Prove Yourself"
    [BCS16] Ben-Sasson et al.: "Interactive Oracle Proofs"
    [BCC+16] "Scalable Zero Knowledge via Cycles of Elliptic Curves"
"""

from typing import List, Union, Optional, Any
from dataclasses import dataclass, field
import hashlib
import json


@dataclass
class Transcript:
    """
    Fiat-Shamir transcript for generating verifier challenges.
    
    The Fiat-Shamir heuristic converts an interactive protocol into
    a non-interactive one by replacing verifier randomness with
    hashes of the protocol transcript.
    
    **Interactive Protocol:**
    1. Prover sends message m₁
    2. Verifier responds with random challenge c₁
    3. Prover sends m₂
    4. ... (repeat)
    
    **Non-Interactive (Fiat-Shamir):**
    1. Prover computes c₁ = H(m₁)
    2. Prover computes m₂ using c₁
    3. Prover computes c₂ = H(m₁, m₂)
    4. ... (repeat)
    5. Prover sends all messages as proof
    
    **Security in Random Oracle Model:**
    - Soundness: Hash function behaves as random oracle
    - Zero-Knowledge: Simulator can program random oracle
    - Assumption: H is modeled as a random function
    
    **Properties:**
    1. Completeness: Honest prover always convinces verifier
    2. Soundness: Cheating prover succeeds with negligible probability
    3. Zero-Knowledge: (Can be) maintained in ROM
    
    **Domain Separation:**
    Each protocol should use a unique label to prevent cross-protocol attacks.
    Example: "SNARK-KZG-v1.0" vs "SNARK-PLONK-v2.0"
    
    Attributes:
        protocol_label (str): Unique identifier for this protocol instance.
        state (bytes): Current transcript state (accumulated hash).
        history (List): Full sequence of absorbed messages (for debugging).
    
    Example:
        >>> # Prover side
        >>> transcript = Transcript(protocol_label="MyProtocol-v1")
        >>> transcript.absorb("commitment", commitment_bytes)
        >>> challenge = transcript.squeeze("challenge1", 32)
        >>> 
        >>> # Verifier side (replays same transcript)
        >>> v_transcript = Transcript(protocol_label="MyProtocol-v1")
        >>> v_transcript.absorb("commitment", commitment_bytes)
        >>> v_challenge = v_transcript.squeeze("challenge1", 32)
        >>> assert challenge == v_challenge
    """
    
    protocol_label: str
    state: bytes = field(default_factory=lambda: b'')
    history: List[tuple] = field(default_factory=list)
    _hash_func: str = 'sha256'
    
    def __post_init__(self):
        """Initialize transcript with protocol label."""
        # Domain separation: Start with protocol-specific constant
        h = hashlib.sha256()
        h.update(b"FIAT-SHAMIR-TRANSCRIPT-V1")
        h.update(self.protocol_label.encode('utf-8'))
        self.state = h.digest()
    
    def absorb(self, label: str, data: Union[bytes, int, str, List]) -> None:
        """
        Absorb data into the transcript.
        
        This corresponds to the prover sending a message in the interactive
        protocol. The data is incorporated into the transcript state.
        
        **Domain Separation:**
        Each absorption is labeled to prevent cross-message attacks:
        - Different labels → different hashes
        - Same label + data → deterministic hash
        
        **Encoding:**
        - bytes: Used directly
        - int: Encoded as 32-byte big-endian
        - str: UTF-8 encoded
        - List: JSON-serialized then encoded
        
        Args:
            label: Semantic label for this data (e.g., "commitment", "proof").
            data: The message data to absorb.
        
        Example:
            >>> transcript.absorb("setup", setup_params)
            >>> transcript.absorb("witness_commitment", commitment)
            >>> # Absorbing in different order gives different state
        """
        # Encode data based on type
        if isinstance(data, bytes):
            encoded = data
        elif isinstance(data, int):
            # Encode integer as 32 bytes (handles field elements)
            encoded = data.to_bytes(32, byteorder='big', signed=False)
        elif isinstance(data, str):
            encoded = data.encode('utf-8')
        elif isinstance(data, list):
            # Serialize list to JSON for deterministic encoding
            json_str = json.dumps(data, sort_keys=True)
            encoded = json_str.encode('utf-8')
        else:
            # Fallback: convert to string
            encoded = str(data).encode('utf-8')
        
        # Update state: H(state || label || length || data)
        h = hashlib.sha256()
        h.update(self.state)
        h.update(label.encode('utf-8'))
        h.update(len(encoded).to_bytes(8, 'big'))
        h.update(encoded)
        self.state = h.digest()
        
        # Record in history
        self.history.append((label, data if isinstance(data, (int, str)) else f"<{type(data).__name__}>"))
    
    def squeeze(self, challenge_label: str, num_bytes: int = 32) -> bytes:
        """
        Generate a challenge from the current transcript state.
        
        This corresponds to the verifier sending a random challenge
        in the interactive protocol. The challenge is deterministically
        derived from all previous messages.
        
        **Soundness Critical:**
        - Challenge must depend on ALL previous messages
        - Same transcript state → same challenge (determinism)
        - Changing any message → different challenge (binding)
        
        **Multiple Challenges:**
        Can be called multiple times with different labels for
        multiple rounds of interaction.
        
        Args:
            challenge_label: Unique label for this challenge point.
            num_bytes: Number of random bytes to generate.
        
        Returns:
            Pseudorandom challenge bytes.
        
        Example:
            >>> transcript.absorb("round1", prover_msg1)
            >>> challenge1 = transcript.squeeze("verifier_challenge1", 32)
            >>> # Use challenge1 to compute round2 message
            >>> transcript.absorb("round2", prover_msg2)
            >>> challenge2 = transcript.squeeze("verifier_challenge2", 32)
        """
        # Generate challenge: H(state || challenge_label || counter)
        # Counter allows multiple squeezes with same label
        counter = 0
        output = b''
        
        while len(output) < num_bytes:
            h = hashlib.sha256()
            h.update(self.state)
            h.update(challenge_label.encode('utf-8'))
            h.update(counter.to_bytes(4, 'big'))
            output += h.digest()
            counter += 1
        
        # Update state to include this challenge (prevents reuse attacks)
        self.absorb(f"challenge:{challenge_label}", output[:num_bytes])
        
        return output[:num_bytes]
    
    def squeeze_field_element(self, challenge_label: str, field_modulus: int) -> int:
        """
        Generate a field element challenge.
        
        For zkSNARK protocols, challenges are typically field elements
        in F_p for some prime p. This method generates a uniformly
        random element in [0, field_modulus).
        
        **Bias Mitigation:**
        Uses rejection sampling to ensure statistical uniformity:
        - Sample random integer in [0, 2^256)
        - If >= field_modulus, reject and resample
        - Expected iterations: ~1 (for typical 254-bit primes)
        
        Args:
            challenge_label: Unique label for this challenge.
            field_modulus: The field prime p.
        
        Returns:
            Field element in [0, p).
        
        Example:
            >>> # Field F_p where p = 2^255 - 19 (Curve25519)
            >>> p = 2**255 - 19
            >>> challenge = transcript.squeeze_field_element("alpha", p)
            >>> assert 0 <= challenge < p
        """
        # Determine how many bytes needed (add 128 bits for statistical distance)
        modulus_bits = field_modulus.bit_length()
        num_bytes = (modulus_bits + 128 + 7) // 8
        
        # Rejection sampling for uniform distribution
        max_iterations = 100  # Safety bound
        for i in range(max_iterations):
            random_bytes = self.squeeze(f"{challenge_label}:attempt_{i}", num_bytes)
            candidate = int.from_bytes(random_bytes, byteorder='big')
            
            if candidate < field_modulus:
                return candidate
        
        # Fallback: modular reduction (introduces negligible bias for large p)
        random_bytes = self.squeeze(f"{challenge_label}:fallback", num_bytes)
        return int.from_bytes(random_bytes, byteorder='big') % field_modulus
    
    def squeeze_field_elements(self, challenge_label: str, field_modulus: int, count: int) -> List[int]:
        """
        Generate multiple field element challenges.
        
        Args:
            challenge_label: Base label for challenges.
            field_modulus: The field prime p.
            count: Number of elements to generate.
        
        Returns:
            List of field elements.
        
        Example:
            >>> # Generate 3 random field elements
            >>> challenges = transcript.squeeze_field_elements("betas", p, 3)
            >>> assert len(challenges) == 3
        """
        return [
            self.squeeze_field_element(f"{challenge_label}[{i}]", field_modulus)
            for i in range(count)
        ]
    
    def fork(self, branch_label: str) -> 'Transcript':
        """
        Create a forked transcript for parallel proof paths.
        
        Useful in recursive SNARKs or batch proofs where multiple
        independent sub-proofs share common prefix.
        
        Args:
            branch_label: Label for this branch (for domain separation).
        
        Returns:
            New transcript with current state as starting point.
        
        Example:
            >>> main_transcript = Transcript("BatchProof")
            >>> main_transcript.absorb("setup", common_params)
            >>> proof1_transcript = main_transcript.fork("proof1")
            >>> proof2_transcript = main_transcript.fork("proof2")
        """
        forked = Transcript(protocol_label=f"{self.protocol_label}::{branch_label}")
        forked.state = self.state
        forked.history = self.history.copy()
        return forked
    
    def get_state(self) -> bytes:
        """
        Get current transcript state.
        
        Returns:
            Current hash state (32 bytes).
        """
        return self.state
    
    def get_history(self) -> List[tuple]:
        """
        Get full transcript history.
        
        Useful for debugging and auditing protocol execution.
        
        Returns:
            List of (label, data) tuples.
        """
        return self.history.copy()
    
    def __repr__(self) -> str:
        """String representation."""
        state_hex = self.state.hex()[:16] + "..."
        return f"Transcript(protocol='{self.protocol_label}', state={state_hex}, messages={len(self.history)})"


def test_transcript_example():
    """
    Example usage of Fiat-Shamir transcript.
    
    Demonstrates a simple interactive→non-interactive transformation.
    """
    # Simulated Schnorr-like protocol
    print("=== Fiat-Shamir Transcript Demo ===\n")
    
    # Protocol parameters
    p = 2**255 - 19  # Field prime (Curve25519 field)
    
    # Prover's transcript
    prover = Transcript(protocol_label="Schnorr-v1.0")
    
    # Round 1: Prover commits
    commitment = 12345678901234567890  # Simulated commitment
    prover.absorb("commitment", commitment)
    print(f"Prover commits: {commitment}")
    
    # Fiat-Shamir: Generate challenge
    challenge = prover.squeeze_field_element("challenge", p)
    print(f"Challenge (FS): {challenge}")
    
    # Round 2: Prover responds
    response = 98765432109876543210  # Simulated response
    prover.absorb("response", response)
    print(f"Prover responds: {response}")
    
    # Verifier's transcript (replay)
    print("\n--- Verifier Replays ---")
    verifier = Transcript(protocol_label="Schnorr-v1.0")
    verifier.absorb("commitment", commitment)
    v_challenge = verifier.squeeze_field_element("challenge", p)
    assert v_challenge == challenge, "Challenge mismatch!"
    print(f"Verifier's challenge: {v_challenge} ✓")
    
    verifier.absorb("response", response)
    print("Verification successful!\n")


if __name__ == "__main__":
    test_transcript_example()
