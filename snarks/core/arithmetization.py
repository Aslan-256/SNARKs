"""
Arithmetization: Converting Arithmetic Circuits to Constraint Systems.

This module implements the conversion pipeline:
    Arithmetic Circuit → R1CS → QAP

1. R1CS (Rank-1 Constraint System): Represents the circuit as a system
   of bilinear constraints: (A·w) ∘ (B·w) = (C·w) where w is the witness vector.

2. QAP (Quadratic Arithmetic Program): Converts R1CS into polynomial form
   using Lagrange interpolation. The constraint becomes:
   A(x)·B(x) - C(x) = H(x)·t(x)

This follows the construction described in zkSNARK literature (Gennaro et al., 2013).
"""

from typing import List, Tuple, Dict, Optional
import math
from .circuit import ArithmeticCircuit, Gate, Wire, GateType
from .finite_field import FiniteField
from .polynomial import Polynomial


class R1CS:
    """
    Rank-1 Constraint System.
    
    Represents arithmetic circuit constraints as:
        (A·w) ∘ (B·w) = (C·w)
    
    where:
    - w is the witness vector (variable assignment)
    - A, B, C are constraint matrices
    - ∘ denotes element-wise (Hadamard) product
    
    Each row represents one constraint (typically one multiplication gate).
    
    Attributes:
        A (List[List[int]]): Left input matrix.
        B (List[List[int]]): Right input matrix.
        C (List[List[int]]): Output matrix.
        num_variables (int): Total number of variables (wires).
        num_constraints (int): Number of constraints (rows).
        modulus (int): Field modulus.
        wire_to_index (Dict[Wire, int]): Maps circuit wires to witness indices.
        public_indices (List[int]): Indices of public input variables.
        private_indices (List[int]): Indices of private witness variables.
    """
    
    def __init__(
        self,
        A: List[List[int]],
        B: List[List[int]],
        C: List[List[int]],
        num_variables: int,
        num_constraints: int,
        modulus: int,
        wire_to_index: Dict[Wire, int],
        public_indices: List[int],
        private_indices: List[int]
    ):
        """
        Initialize an R1CS instance.
        
        Args:
            A, B, C: Constraint matrices (num_constraints × num_variables).
            num_variables: Number of variables in witness.
            num_constraints: Number of constraints.
            modulus: Field modulus.
            wire_to_index: Mapping from circuit wires to indices.
            public_indices: Indices of public inputs.
            private_indices: Indices of private inputs.
        """
        self.A = A
        self.B = B
        self.C = C
        self.num_variables = num_variables
        self.num_constraints = num_constraints
        self.modulus = modulus
        self.wire_to_index = wire_to_index
        self.public_indices = public_indices
        self.private_indices = private_indices
    
    def is_satisfied(self, witness: List[int]) -> bool:
        """
        Check if a witness satisfies the R1CS constraints.
        
        Verifies: (A·w) ∘ (B·w) = (C·w) for each constraint.
        
        Args:
            witness: Variable assignment vector.
        
        Returns:
            True if all constraints are satisfied.
        """
        if len(witness) != self.num_variables:
            return False
        
        # Convert to field elements
        w = [FiniteField(val, self.modulus) for val in witness]
        
        # Check each constraint
        for i in range(self.num_constraints):
            # Compute A[i]·w
            a_dot_w = FiniteField(0, self.modulus)
            for j in range(self.num_variables):
                a_dot_w = a_dot_w + FiniteField(self.A[i][j], self.modulus) * w[j]
            
            # Compute B[i]·w
            b_dot_w = FiniteField(0, self.modulus)
            for j in range(self.num_variables):
                b_dot_w = b_dot_w + FiniteField(self.B[i][j], self.modulus) * w[j]
            
            # Compute C[i]·w
            c_dot_w = FiniteField(0, self.modulus)
            for j in range(self.num_variables):
                c_dot_w = c_dot_w + FiniteField(self.C[i][j], self.modulus) * w[j]
            
            # Check: (A·w) * (B·w) = C·w
            if a_dot_w * b_dot_w != c_dot_w:
                return False
        
        return True
    
    def __repr__(self) -> str:
        return (
            f"R1CS(constraints={self.num_constraints}, "
            f"variables={self.num_variables}, "
            f"modulus={self.modulus})"
        )


class QAPInstance:
    """
    Quadratic Arithmetic Program.
    
    Represents R1CS in polynomial form using Lagrange interpolation.
    The constraint system becomes:
        A(x)·B(x) - C(x) = H(x)·t(x)
    
    where:
    - A(x), B(x), C(x) are polynomials encoding the constraint matrices
    - t(x) is the target polynomial (vanishes at evaluation points)
    - H(x) is the quotient polynomial (proof of satisfaction)
    
    Attributes:
        A_polys (List[Polynomial]): One polynomial per variable (A matrix columns).
        B_polys (List[Polynomial]): One polynomial per variable (B matrix columns).
        C_polys (List[Polynomial]): One polynomial per variable (C matrix columns).
        target (Polynomial): Target polynomial t(x) = ∏(x - rᵢ).
        num_variables (int): Number of variables.
        num_constraints (int): Number of constraints.
        modulus (int): Field modulus.
        eval_points (List[int]): Evaluation domain {r₁, r₂, ..., rₙ}.
        public_indices (List[int]): Indices of public variables.
        private_indices (List[int]): Indices of private variables.
    """
    
    def __init__(
        self,
        A_polys: List[Polynomial],
        B_polys: List[Polynomial],
        C_polys: List[Polynomial],
        target: Polynomial,
        num_variables: int,
        num_constraints: int,
        modulus: int,
        eval_points: List[int],
        public_indices: List[int],
        private_indices: List[int]
    ):
        """
        Initialize a QAP instance.
        
        Args:
            A_polys, B_polys, C_polys: Polynomials for each variable.
            target: Target polynomial.
            num_variables: Number of variables.
            num_constraints: Number of constraints.
            modulus: Field modulus.
            eval_points: Evaluation domain.
            public_indices: Public input indices.
            private_indices: Private input indices.
        """
        self.A_polys = A_polys
        self.B_polys = B_polys
        self.C_polys = C_polys
        self.target = target
        self.num_variables = num_variables
        self.num_constraints = num_constraints
        self.modulus = modulus
        self.eval_points = eval_points
        self.public_indices = public_indices
        self.private_indices = private_indices
    
    def __repr__(self) -> str:
        return (
            f"QAPInstance(variables={self.num_variables}, "
            f"constraints={self.num_constraints}, "
            f"degree={self.target.degree()})"
        )


class Arithmetization:
    """
    Converts Arithmetic Circuits to R1CS and QAP.
    
    This class implements the standard arithmetization pipeline used in
    zkSNARKs like Groth16 and Pinocchio.
    
    Pipeline:
    1. Circuit → R1CS: Flatten circuit gates into constraint matrices
    2. R1CS → QAP: Apply Lagrange interpolation to get polynomials
    """
    
    @staticmethod
    def circuit_to_r1cs(circuit: ArithmeticCircuit) -> R1CS:
        """
        Convert an arithmetic circuit to R1CS (Rank-1 Constraint System).
        
        Algorithm:
        1. Assign each wire a unique variable index
        2. For each multiplication gate, create a constraint:
           (left wire) * (right wire) = (output wire)
        3. Handle addition gates by folding into linear combinations
        4. Build constraint matrices A, B, C
        
        Args:
            circuit: The arithmetic circuit to convert.
        
        Returns:
            R1CS representation of the circuit.
        
        Note:
            - Each multiplication gate → one constraint
            - Addition gates are handled via linear combinations
            - Constant gates are substituted into constraints
        """
        modulus = circuit.modulus
        
        # Step 1: Assign indices to wires (variables in witness vector)
        # Index 0 is reserved for the constant ONE
        wire_to_index: Dict[Wire, int] = {circuit.ONE: 0}
        current_index = 1
        
        # Assign indices to all other wires in topological order
        for gate in circuit.gates:
            if gate.output not in wire_to_index and gate.output != circuit.ONE:
                wire_to_index[gate.output] = current_index
                current_index += 1
        
        num_variables = len(wire_to_index)
        
        # Track public and private indices
        public_indices = [0]  # Index 0 (ONE) is always public
        private_indices = []
        
        for wire in circuit.public_inputs:
            if wire in wire_to_index:
                public_indices.append(wire_to_index[wire])
        
        for wire in circuit.private_inputs:
            if wire in wire_to_index:
                private_indices.append(wire_to_index[wire])
        
        # Step 2: Build constraints from gates
        # We'll process gates and expand addition chains
        
        # First pass: compute values for each wire as linear combinations
        # wire_expr[wire] = {index: coefficient} representing Σ(coeff * var[index])
        wire_expr: Dict[Wire, Dict[int, int]] = {}
        
        def get_expr(wire: Wire) -> Dict[int, int]:
            """Get linear expression for a wire."""
            if wire in wire_expr:
                return wire_expr[wire].copy()
            # Default: wire = 1 * wire_index
            return {wire_to_index[wire]: 1}
        
        def add_expr(expr1: Dict[int, int], expr2: Dict[int, int]) -> Dict[int, int]:
            """Add two linear expressions."""
            result = expr1.copy()
            for idx, coeff in expr2.items():
                result[idx] = (result.get(idx, 0) + coeff) % modulus
            return result
        
        # Process gates to build expressions
        for gate in circuit.gates:
            if gate.gate_type == GateType.CONST:
                # Constant = coeff * ONE
                wire_expr[gate.output] = {0: gate.const_value % modulus}
            
            elif gate.gate_type == GateType.INPUT:
                # Input = 1 * itself
                wire_expr[gate.output] = {wire_to_index[gate.output]: 1}
            
            elif gate.gate_type == GateType.ADD:
                # Addition: out = left + right (linear combination)
                left_expr = get_expr(gate.inputs[0])
                right_expr = get_expr(gate.inputs[1])
                wire_expr[gate.output] = add_expr(left_expr, right_expr)
            
            elif gate.gate_type == GateType.MUL:
                # Multiplication: handled in constraint generation
                # Output gets its own variable
                wire_expr[gate.output] = {wire_to_index[gate.output]: 1}
        
        # Step 3: Generate constraints (one per multiplication gate)
        constraints_A: List[List[int]] = []
        constraints_B: List[List[int]] = []
        constraints_C: List[List[int]] = []
        
        for gate in circuit.gates:
            if gate.gate_type == GateType.MUL:
                # Constraint: (A·w) * (B·w) = (C·w)
                # where A represents left input, B represents right input,
                # C represents output
                
                left_expr = get_expr(gate.inputs[0])
                right_expr = get_expr(gate.inputs[1])
                output_expr = get_expr(gate.output)
                
                # Build constraint row vectors
                A_row = [0] * num_variables
                B_row = [0] * num_variables
                C_row = [0] * num_variables
                
                # A row: left input expression
                for idx, coeff in left_expr.items():
                    A_row[idx] = coeff % modulus
                
                # B row: right input expression
                for idx, coeff in right_expr.items():
                    B_row[idx] = coeff % modulus
                
                # C row: output expression
                for idx, coeff in output_expr.items():
                    C_row[idx] = coeff % modulus
                
                constraints_A.append(A_row)
                constraints_B.append(B_row)
                constraints_C.append(C_row)
        
        num_constraints = len(constraints_A)
        
        return R1CS(
            A=constraints_A,
            B=constraints_B,
            C=constraints_C,
            num_variables=num_variables,
            num_constraints=num_constraints,
            modulus=modulus,
            wire_to_index=wire_to_index,
            public_indices=public_indices,
            private_indices=private_indices
        )
    
    @staticmethod
    def r1cs_to_qap(r1cs: R1CS) -> QAPInstance:
        """
        Convert R1CS to QAP using Lagrange interpolation.
        
        Algorithm (following Gennaro et al., 2013):
        1. Choose evaluation domain {r₁, ..., rₙ} where n = num_constraints
        2. For each variable j, create polynomials:
           - Aⱼ(x): interpolates (rᵢ, A[i][j]) for i=1..n
           - Bⱼ(x): interpolates (rᵢ, B[i][j]) for i=1..n
           - Cⱼ(x): interpolates (rᵢ, C[i][j]) for i=1..n
        3. Create target polynomial: t(x) = ∏(x - rᵢ)
        
        Property: For valid witness w,
            A(x)·B(x) - C(x) is divisible by t(x)
        where A(x) = Σ wⱼAⱼ(x), B(x) = Σ wⱼBⱼ(x), C(x) = Σ wⱼCⱼ(x)
        
        Args:
            r1cs: The R1CS to convert.
        
        Returns:
            QAP instance with interpolated polynomials.
        """
        modulus = r1cs.modulus
        n = r1cs.num_constraints
        m = r1cs.num_variables
        
        # Step 1: Choose evaluation domain
        # Use {1, 2, 3, ..., n} for simplicity
        eval_points = list(range(1, n + 1))
        
        # Step 2: Interpolate polynomials for each variable
        A_polys: List[Polynomial] = []
        B_polys: List[Polynomial] = []
        C_polys: List[Polynomial] = []
        
        for j in range(m):
            # Extract column j from matrices (values at each constraint)
            A_values = [r1cs.A[i][j] for i in range(n)]
            B_values = [r1cs.B[i][j] for i in range(n)]
            C_values = [r1cs.C[i][j] for i in range(n)]
            
            # Interpolate: find polynomial passing through (rᵢ, value[i])
            A_poly = Arithmetization._lagrange_interpolation(
                eval_points, A_values, modulus
            )
            B_poly = Arithmetization._lagrange_interpolation(
                eval_points, B_values, modulus
            )
            C_poly = Arithmetization._lagrange_interpolation(
                eval_points, C_values, modulus
            )
            
            A_polys.append(A_poly)
            B_polys.append(B_poly)
            C_polys.append(C_poly)
        
        # Step 3: Create target polynomial t(x) = ∏(x - rᵢ)
        target = Arithmetization._create_target_polynomial(eval_points, modulus)
        
        return QAPInstance(
            A_polys=A_polys,
            B_polys=B_polys,
            C_polys=C_polys,
            target=target,
            num_variables=m,
            num_constraints=n,
            modulus=modulus,
            eval_points=eval_points,
            public_indices=r1cs.public_indices,
            private_indices=r1cs.private_indices
        )
    
    @staticmethod
    def _lagrange_interpolation(
        points: List[int],
        values: List[int],
        modulus: int
    ) -> Polynomial:
        """
        Lagrange interpolation: find polynomial passing through given points.
        
        Given points (x₁, y₁), ..., (xₙ, yₙ), compute polynomial:
            L(x) = Σ yᵢ · ℓᵢ(x)
        where ℓᵢ(x) = ∏_{j≠i} (x - xⱼ)/(xᵢ - xⱼ)
        
        Args:
            points: x-coordinates [x₁, ..., xₙ].
            values: y-coordinates [y₁, ..., yₙ].
            modulus: Field modulus.
        
        Returns:
            Interpolated polynomial over finite field.
        """
        if len(points) != len(values):
            raise ValueError("Points and values must have same length")
        
        n = len(points)
        
        # Convert to field elements
        x_points = [FiniteField(p, modulus) for p in points]
        y_values = [FiniteField(v, modulus) for v in values]
        
        # Initialize result as zero polynomial
        result = Polynomial.zero(modulus)
        
        # Compute each Lagrange basis polynomial and accumulate
        for i in range(n):
            # Compute ℓᵢ(x) = ∏_{j≠i} (x - xⱼ)/(xᵢ - xⱼ)
            basis = Polynomial([FiniteField(1, modulus)])  # Start with 1
            
            for j in range(n):
                if i != j:
                    # Multiply by (x - xⱼ)
                    numerator = Polynomial([
                        -x_points[j],
                        FiniteField(1, modulus)
                    ])  # -xⱼ + 1·x
                    basis = basis * numerator
                    
                    # Divide by (xᵢ - xⱼ)
                    denominator = x_points[i] - x_points[j]
                    basis = basis * denominator.inverse()
            
            # Add yᵢ · ℓᵢ(x) to result
            result = result + (basis * y_values[i])
        
        return result
    
    @staticmethod
    def _create_target_polynomial(points: List[int], modulus: int) -> Polynomial:
        """
        Create target polynomial t(x) = ∏(x - rᵢ).
        
        The target polynomial vanishes at all evaluation points.
        
        Args:
            points: Evaluation points [r₁, ..., rₙ].
            modulus: Field modulus.
        
        Returns:
            Target polynomial.
        """
        # Start with t(x) = 1
        result = Polynomial([FiniteField(1, modulus)])
        
        # Multiply by (x - rᵢ) for each point
        for point in points:
            # (x - point) = -point + 1·x
            factor = Polynomial([
                FiniteField(-point, modulus),
                FiniteField(1, modulus)
            ])
            result = result * factor
        
        return result
    
    @staticmethod
    def circuit_to_qap(circuit: ArithmeticCircuit) -> QAPInstance:
        """
        Direct conversion from circuit to QAP (convenience method).
        
        Combines circuit_to_r1cs and r1cs_to_qap.
        
        Args:
            circuit: Arithmetic circuit.
        
        Returns:
            QAP instance.
        
        Example:
            >>> circuit = ArithmeticCircuit(modulus=97)
            >>> # ... build circuit ...
            >>> qap = Arithmetization.circuit_to_qap(circuit)
        """
        r1cs = Arithmetization.circuit_to_r1cs(circuit)
        return Arithmetization.r1cs_to_qap(r1cs)
