"""
Quadratic Arithmetic Program (QAP) implementation.

QAP is a fundamental building block for many zk-SNARK constructions like Groth16.
It transforms arithmetic circuits into polynomial equations over finite fields.

This implementation follows the standard zkSNARK pipeline:
    Circuit → R1CS → QAP → Trusted Setup → Prove/Verify

Key References:
- Gennaro et al. (2013): "Quadratic Span Programs and Succinct NIZKs"
- Parno et al. (2013): "Pinocchio: Nearly Practical Verifiable Computation"
"""

from typing import List, Tuple, Optional, Dict
import secrets
from ..core.finite_field import FiniteField
from ..core.polynomial import Polynomial
from ..core.circuit import ArithmeticCircuit, Wire
from ..core.arithmetization import Arithmetization, QAPInstance as QAPInstanceBase


class ProvingKey:
    """
    Proving Key (pk) for QAP zkSNARK.
    
    In a real zkSNARK (like Groth16), this would contain elliptic curve points
    encoding encrypted evaluations of polynomials at secret point τ.
    
    For this educational implementation, we store:
    - The QAP instance (polynomials)
    - Secret evaluation point τ (normally hidden via pairing crypto)
    - Precomputed values for efficiency
    
    Attributes:
        qap (QAPInstanceBase): The QAP instance (polynomials A, B, C, t).
        tau (int): Secret evaluation point (in practice, encrypted).
        modulus (int): Field modulus.
        wire_to_index (Dict[Wire, int]): Mapping from circuit wires to witness indices.
    """
    
    def __init__(
        self,
        qap: QAPInstanceBase,
        tau: int,
        modulus: int,
        wire_to_index: Dict[Wire, int]
    ):
        """
        Initialize proving key.
        
        Args:
            qap: QAP instance.
            tau: Secret evaluation point.
            modulus: Field modulus.
            wire_to_index: Wire to index mapping.
        """
        self.qap = qap
        self.tau = tau
        self.modulus = modulus
        self.wire_to_index = wire_to_index
    
    def __repr__(self) -> str:
        return f"ProvingKey(variables={self.qap.num_variables}, constraints={self.qap.num_constraints})"


class VerificationKey:
    """
    Verification Key (vk) for QAP zkSNARK.
    
    In real zkSNARKs, this contains elliptic curve points for pairing checks.
    For this educational version, we store:
    - QAP structure (needed for verification equation)
    - Public input information
    
    Attributes:
        qap (QAPInstanceBase): QAP instance (for verification checks).
        public_indices (List[int]): Indices of public inputs in witness.
        modulus (int): Field modulus.
    """
    
    def __init__(
        self,
        qap: QAPInstanceBase,
        public_indices: List[int],
        modulus: int
    ):
        """
        Initialize verification key.
        
        Args:
            qap: QAP instance.
            public_indices: Public input indices.
            modulus: Field modulus.
        """
        self.qap = qap
        self.public_indices = public_indices
        self.modulus = modulus
    
    def __repr__(self) -> str:
        return f"VerificationKey(public_inputs={len(self.public_indices)})"


class QAPProof:
    """
    zkSNARK proof for QAP.
    
    In real zkSNARKs (Groth16), a proof consists of 3 elliptic curve points.
    For this educational implementation, we store:
    - H(τ): Evaluation of quotient polynomial at secret point
    - Witness vector (for verification; hidden in real zkSNARKs)
    
    Attributes:
        H_poly (Polynomial): Quotient polynomial H(x) where A·B - C = H·t.
        witness (List[FiniteField]): Full witness assignment (including public inputs).
    """
    
    def __init__(self, H_poly: Polynomial, witness: List[FiniteField]):
        """
        Initialize QAP proof.
        
        Args:
            H_poly: Quotient polynomial proving divisibility.
            witness: Full variable assignment.
        """
        self.H_poly = H_poly
        self.witness = witness
    
    def __repr__(self) -> str:
        return f"QAPProof(H_degree={self.H_poly.degree()}, witness_size={len(self.witness)})"


class QAP:
    """
    Quadratic Arithmetic Program zkSNARK system.
    
    Implements a simplified zkSNARK following the Pinocchio/Groth16 paradigm:
    
    1. Setup (Trusted Setup): Takes a circuit, performs arithmetization,
       and generates proving/verification keys (CRS/SRS).
       In practice, this involves sampling secret randomness (τ, α, β, γ, δ)
       and encoding polynomial evaluations in elliptic curve groups.
    
    2. Prove: Prover computes witness, evaluates QAP polynomials, computes
       quotient polynomial H(x), and generates a succinct proof π.
    
    3. Verify: Verifier checks the proof using pairing equations (simulated here).
    
    Protocol Flow:
        Circuit → R1CS → QAP → Setup(pk, vk) → Prove(π) → Verify(bool)
    
    Attributes:
        circuit (ArithmeticCircuit): The arithmetic circuit being proven.
        qap (QAPInstanceBase): QAP polynomials derived from circuit.
        wire_to_index (Dict[Wire, int]): Maps circuit wires to witness indices.
    """
    
    def __init__(self, circuit: ArithmeticCircuit):
        """
        Initialize QAP from an arithmetic circuit.
        
        Performs arithmetization: Circuit → R1CS → QAP.
        
        Args:
            circuit: Arithmetic circuit representing the computation.
        
        Example:
            >>> circuit = ArithmeticCircuit(modulus=97)
            >>> x = circuit.add_input(is_public=False)
            >>> y = circuit.add_input(is_public=False)
            >>> z = circuit.mul(x, y)
            >>> circuit.set_output(z)
            >>> qap = QAP(circuit)
        """
        self.circuit = circuit
        
        # Step 1: Circuit → R1CS
        r1cs = Arithmetization.circuit_to_r1cs(circuit)
        self.wire_to_index = r1cs.wire_to_index
        
        # Step 2: R1CS → QAP
        self.qap = Arithmetization.r1cs_to_qap(r1cs)
    
    def setup(self) -> Tuple[ProvingKey, VerificationKey]:
        """
        Perform trusted setup to generate proving and verification keys.
        
        In real zkSNARKs (Groth16), this involves:
        1. Sample secret randomness: τ, α, β, γ, δ ← 𝔽ₚ
        2. Compute encrypted powers: [τⁱ]₁, [τⁱ]₂ for i=0..d
        3. Encode QAP polynomials: [Aᵢ(τ)]₁, [Bᵢ(τ)]₂, [Cᵢ(τ)]₁
        4. Split into pk (proving key) and vk (verification key)
        
        For this educational version:
        - We sample τ but keep it in the clear (insecure, for learning)
        - We skip elliptic curve pairing machinery
        - We simulate the "encrypted" polynomial evaluations
        
        Returns:
            Tuple of (proving_key, verification_key).
        
        Security Note:
            The secret τ must be destroyed after setup! In practice, this uses
            multi-party computation (MPC) ceremonies or universal setups.
        
        Example:
            >>> pk, vk = qap.setup()
        """
        modulus = self.circuit.modulus
        
        # Step 1: Sample secret randomness
        # In practice: τ, α, β, γ, δ sampled uniformly from 𝔽ₚ
        # For educational purposes, we use a cryptographic RNG
        tau = secrets.randbelow(modulus - 1) + 1  # τ ∈ [1, p-1]
        
        # In full Groth16, we'd also sample α, β, γ, δ and compute:
        # - g^{α}, g^{β}, g^{δ} in G₁
        # - h^{β}, h^{γ}, h^{δ} in G₂  
        # - {g^{τⁱ}}ᵢ₌₀ⁿ, {h^{τⁱ}}ᵢ₌₀ⁿ
        # For simplicity, we just use τ
        
        # Create proving key (contains QAP + secrets)
        pk = ProvingKey(
            qap=self.qap,
            tau=tau,
            modulus=modulus,
            wire_to_index=self.wire_to_index
        )
        
        # Create verification key (public, for verifiers)
        vk = VerificationKey(
            qap=self.qap,
            public_indices=self.qap.public_indices,
            modulus=modulus
        )
        
        # CRITICAL: In production, τ and other secrets must be securely erased!
        # This is why MPC ceremonies are used for trusted setups.
        
        return pk, vk
    
    def prove(
        self,
        pk: ProvingKey,
        public_inputs: Dict[Wire, int],
        witness: Dict[Wire, int]
    ) -> QAPProof:
        """
        Generate a zkSNARK proof.
        
        The prover:
        1. Constructs full witness vector w (public inputs + private witness)
        2. Evaluates circuit to verify satisfiability
        3. Computes QAP polynomials: A(x) = Σ wᵢAᵢ(x), B(x) = Σ wᵢBᵢ(x), C(x) = Σ wᵢCᵢ(x)
        4. Computes quotient: H(x) = (A(x)·B(x) - C(x)) / t(x)
        5. In real zkSNARK: evaluate at secret τ and encode in elliptic curves
        
        Args:
            pk: Proving key from setup.
            public_inputs: Assignment to public input wires {wire: value}.
            witness: Assignment to private witness wires {wire: value}.
        
        Returns:
            QAP proof π.
        
        Raises:
            ValueError: If circuit is not satisfied or inputs are invalid.
        
        Example:
            >>> # Circuit: out = x * y
            >>> proof = qap.prove(pk, {output: 12}, {x: 3, y: 4})
        """
        modulus = pk.modulus
        
        # Step 1: Merge public and private inputs
        all_inputs = {**public_inputs, **witness}
        
        # Step 2: Evaluate circuit to check satisfiability
        try:
            wire_values = self.circuit.evaluate(all_inputs)
        except (ValueError, KeyError) as e:
            raise ValueError(f"Circuit not satisfied: {e}")
        
        # Step 3: Build full witness vector
        # witness[0] is always 1 (the constant ONE wire)
        witness_vector = [FiniteField(0, modulus)] * pk.qap.num_variables
        
        for wire, index in pk.wire_to_index.items():
            if wire in wire_values:
                witness_vector[index] = wire_values[wire]
            elif wire == self.circuit.ONE:
                witness_vector[index] = FiniteField(1, modulus)
        
        # Step 4: Compute combined QAP polynomials
        # A(x) = Σᵢ wᵢ · Aᵢ(x)
        A_combined = Polynomial.zero(modulus)
        for i, A_poly in enumerate(pk.qap.A_polys):
            A_combined = A_combined + (A_poly * witness_vector[i])
        
        # B(x) = Σᵢ wᵢ · Bᵢ(x)
        B_combined = Polynomial.zero(modulus)
        for i, B_poly in enumerate(pk.qap.B_polys):
            B_combined = B_combined + (B_poly * witness_vector[i])
        
        # C(x) = Σᵢ wᵢ · Cᵢ(x)
        C_combined = Polynomial.zero(modulus)
        for i, C_poly in enumerate(pk.qap.C_polys):
            C_combined = C_combined + (C_poly * witness_vector[i])
        
        # Step 5: Compute quotient polynomial H(x)
        # Constraint: A(x)·B(x) - C(x) = H(x)·t(x)
        # Therefore: H(x) = (A(x)·B(x) - C(x)) / t(x)
        
        numerator = A_combined * B_combined - C_combined
        target = pk.qap.target
        
        # Polynomial division: numerator / target = H
        # For educational implementation, we check divisibility
        H_poly, remainder = numerator.divide(target)
        
        # Divisibility check: remainder should be zero polynomial
        if not remainder.is_zero():
            raise ValueError(
                "QAP constraint not satisfied: A·B - C is not divisible by t(x). "
                "This means the witness does not satisfy the circuit."
            )
        
        # Step 6: In real zkSNARK (Groth16), we would:
        # - Evaluate H(τ) at the secret point
        # - Compute proof elements in elliptic curve groups:
        #   π = (A, B, C) where A, B, C are curve points encoding the proof
        # For this educational version, we return H directly
        
        return QAPProof(H_poly=H_poly, witness=witness_vector)
    
    def verify(
        self,
        vk: VerificationKey,
        public_inputs: Dict[Wire, int],
        proof: QAPProof
    ) -> bool:
        """
        Verify a zkSNARK proof.
        
        The verifier:
        1. Extracts public inputs from proof witness
        2. Checks QAP divisibility constraint: A(x)·B(x) - C(x) = H(x)·t(x)
        3. In real zkSNARK: performs pairing check e(A, B) = e(C, δ) · e(H, t)
        
        Security: The verifier only uses public inputs and the verification key.
        The private witness remains hidden (in real zkSNARKs).
        
        Args:
            vk: Verification key from setup.
            public_inputs: Public input assignment {wire: value}.
            proof: The proof to verify.
        
        Returns:
            True if proof is valid, False otherwise.
        
        Example:
            >>> is_valid = qap.verify(vk, {output: 12}, proof)
            >>> print(f"Proof valid: {is_valid}")
        """
        modulus = vk.modulus
        
        # Step 1: Verify public inputs match
        # In real zkSNARK, public inputs are part of the verification equation
        for wire in public_inputs:
            if wire not in self.wire_to_index:
                return False
            idx = self.wire_to_index[wire]
            expected = FiniteField(public_inputs[wire], modulus)
            if idx < len(proof.witness) and proof.witness[idx] != expected:
                return False
        
        # Step 2: Recompute A(x), B(x), C(x) using witness from proof
        # (In real zkSNARK, this is done via pairing equations without revealing witness)
        A_combined = Polynomial.zero(modulus)
        for i, A_poly in enumerate(vk.qap.A_polys):
            if i < len(proof.witness):
                A_combined = A_combined + (A_poly * proof.witness[i])
        
        B_combined = Polynomial.zero(modulus)
        for i, B_poly in enumerate(vk.qap.B_polys):
            if i < len(proof.witness):
                B_combined = B_combined + (B_poly * proof.witness[i])
        
        C_combined = Polynomial.zero(modulus)
        for i, C_poly in enumerate(vk.qap.C_polys):
            if i < len(proof.witness):
                C_combined = C_combined + (C_poly * proof.witness[i])
        
        # Step 3: Verify divisibility constraint
        # Check: A(x)·B(x) - C(x) = H(x)·t(x)
        left_side = A_combined * B_combined - C_combined
        right_side = proof.H_poly * vk.qap.target
        
        # In real zkSNARK (Groth16), this becomes a pairing check:
        # e([A]₁, [B]₂) = e([C]₁, [δ]₂) · e([H]₁, [t(τ)]₂) · e(public_inputs, [γ]₂)
        # This check is succinct (O(1) group operations) and doesn't reveal witness
        
        return left_side == right_side


# Backward compatibility: Legacy interfaces for existing code

class QAPSetup:
    """Legacy QAPSetup class for backward compatibility."""
    
    def __init__(self, qap_instance, modulus: int = 97):
        """Initialize legacy setup."""
        self.qap_instance = qap_instance
        self.modulus = modulus


def create_simple_qap_example() -> Tuple[QAP, ProvingKey, VerificationKey]:
    """
    Create a simple QAP example: circuit for x * y = z.
    
    Returns:
        Tuple of (qap_system, proving_key, verification_key).
    
    Example:
        >>> qap, pk, vk = create_simple_qap_example()
        >>> # Now use pk to prove and vk to verify
    """
    # Create circuit: z = x * y
    circuit = ArithmeticCircuit(modulus=97)
    x = circuit.add_input(is_public=False, name="x")
    y = circuit.add_input(is_public=False, name="y")
    z = circuit.mul(x, y, name="z")
    circuit.set_output(z)
    
    # Create QAP and setup
    qap = QAP(circuit)
    pk, vk = qap.setup()
    
    return qap, pk, vk


def qap_example() -> Tuple[QAP, QAPProof, ProvingKey, VerificationKey]:
    """
    Complete QAP example with proof generation.
    
    Creates a circuit z = x * y, proves x=3, y=4, z=12, and returns all components.
    
    Returns:
        Tuple of (qap_system, proof, proving_key, verification_key).
    
    Example:
        >>> qap, proof, pk, vk = qap_example()
        >>> is_valid = qap.verify(vk, {qap.circuit.outputs[0]: 12}, proof)
        >>> print(f"Valid: {is_valid}")  # Should print True
    """
    # Create circuit and keys
    qap, pk, vk = create_simple_qap_example()
    
    # Get wire references
    x = qap.circuit.inputs[0]  # First input (x)
    y = qap.circuit.inputs[1]  # Second input (y)
    z = qap.circuit.outputs[0]  # Output (z)
    
    # Create proof: x=3, y=4, z=12
    public_inputs = {z: 12}
    witness = {x: 3, y: 4}
    
    proof = qap.prove(pk, public_inputs, witness)
    
    return qap, proof, pk, vk

