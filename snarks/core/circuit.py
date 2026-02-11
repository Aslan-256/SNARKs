"""
Arithmetic Circuit representation for zk-SNARKs.

This module provides a Directed Acyclic Graph (DAG) representation of arithmetic
circuits over finite fields. Circuits consist of inputs (public and private),
gates (addition and multiplication), and wires connecting them.

The ArithmeticCircuit serves as the foundation for converting computations
into constraint systems (R1CS) and ultimately into QAP form.
"""

from typing import List, Dict, Tuple, Optional, Union
from enum import Enum
from .finite_field import FiniteField


class GateType(Enum):
    """Types of gates in an arithmetic circuit."""
    INPUT = "input"          # Input wire (public or private)
    ADD = "add"              # Addition gate: out = left + right
    MUL = "mul"              # Multiplication gate: out = left * right
    CONST = "const"          # Constant value


class Wire:
    """
    Represents a wire in the circuit carrying a field element.
    
    Each wire has a unique ID and connects gates together. Wires carry
    values during circuit evaluation.
    
    Attributes:
        wire_id (int): Unique identifier for this wire.
        name (str): Optional human-readable name.
    """
    
    def __init__(self, wire_id: int, name: Optional[str] = None):
        """
        Initialize a wire.
        
        Args:
            wire_id: Unique identifier.
            name: Optional descriptive name.
        """
        self.wire_id = wire_id
        self.name = name or f"w{wire_id}"
    
    def __repr__(self) -> str:
        return f"Wire({self.name})"
    
    def __hash__(self) -> int:
        return hash(self.wire_id)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Wire):
            return False
        return self.wire_id == other.wire_id


class Gate:
    """
    Represents a gate in the arithmetic circuit.
    
    Gates perform operations on wires. Supported operations:
    - INPUT: Takes no inputs, represents a circuit input
    - CONST: Constant value
    - ADD: Addition of two inputs
    - MUL: Multiplication of two inputs
    
    Attributes:
        gate_id (int): Unique identifier.
        gate_type (GateType): Type of operation.
        inputs (List[Wire]): Input wires (0 for INPUT/CONST, 2 for ADD/MUL).
        output (Wire): Output wire.
        const_value (Optional[int]): Value for CONST gates.
        is_public (bool): For INPUT gates, whether input is public.
    """
    
    def __init__(
        self,
        gate_id: int,
        gate_type: GateType,
        output: Wire,
        inputs: Optional[List[Wire]] = None,
        const_value: Optional[int] = None,
        is_public: bool = False
    ):
        """
        Initialize a gate.
        
        Args:
            gate_id: Unique identifier.
            gate_type: Type of gate operation.
            output: Output wire.
            inputs: Input wires (required for ADD/MUL).
            const_value: Constant value (for CONST gates).
            is_public: Whether INPUT is public (for INPUT gates).
        """
        self.gate_id = gate_id
        self.gate_type = gate_type
        self.output = output
        self.inputs = inputs or []
        self.const_value = const_value
        self.is_public = is_public
    
    def __repr__(self) -> str:
        if self.gate_type == GateType.INPUT:
            visibility = "public" if self.is_public else "private"
            return f"Gate({self.gate_id}: INPUT[{visibility}] -> {self.output})"
        elif self.gate_type == GateType.CONST:
            return f"Gate({self.gate_id}: CONST[{self.const_value}] -> {self.output})"
        elif self.gate_type in [GateType.ADD, GateType.MUL]:
            op = "+" if self.gate_type == GateType.ADD else "*"
            return f"Gate({self.gate_id}: {self.inputs[0]} {op} {self.inputs[1]} -> {self.output})"
        return f"Gate({self.gate_id})"


class ArithmeticCircuit:
    """
    Arithmetic circuit over a finite field.
    
    Represents a computation as a Directed Acyclic Graph (DAG) of gates
    connected by wires. The circuit supports:
    - Public and private inputs
    - Addition and multiplication gates over a finite field
    - Circuit evaluation for satisfiability checking
    - Conversion to constraint systems (R1CS/QAP)
    
    The circuit is built incrementally using builder methods:
        circuit = ArithmeticCircuit(field_modulus=97)
        x = circuit.add_input(is_public=False, name="x")
        y = circuit.add_input(is_public=False, name="y")
        z = circuit.mul(x, y)
        circuit.set_output(z)
    
    Attributes:
        modulus (int): Prime modulus for the finite field.
        gates (List[Gate]): List of all gates in topological order.
        wires (Dict[int, Wire]): All wires indexed by wire_id.
        inputs (List[Wire]): Input wires (both public and private).
        outputs (List[Wire]): Output wires.
        public_inputs (List[Wire]): Public input wires only.
        private_inputs (List[Wire]): Private (witness) input wires only.
    """
    
    def __init__(self, modulus: int = 97):
        """
        Initialize an empty arithmetic circuit.
        
        Args:
            modulus: Prime modulus for finite field operations (default: 97).
        """
        self.modulus = modulus
        self.gates: List[Gate] = []
        self.wires: Dict[int, Wire] = {}
        self.inputs: List[Wire] = []
        self.outputs: List[Wire] = []
        self.public_inputs: List[Wire] = []
        self.private_inputs: List[Wire] = []
        
        self._next_wire_id = 0
        self._next_gate_id = 0
        
        # Add constant ONE wire (standard in zk-SNARKs)
        self.ONE = self._create_const(1, name="ONE")
    
    def _create_wire(self, name: Optional[str] = None) -> Wire:
        """Create a new wire with a unique ID."""
        wire = Wire(self._next_wire_id, name)
        self.wires[wire.wire_id] = wire
        self._next_wire_id += 1
        return wire
    
    def _create_gate(
        self,
        gate_type: GateType,
        inputs: Optional[List[Wire]] = None,
        const_value: Optional[int] = None,
        is_public: bool = False,
        name: Optional[str] = None
    ) -> Wire:
        """
        Create a new gate and return its output wire.
        
        Args:
            gate_type: Type of gate.
            inputs: Input wires.
            const_value: Value for CONST gates.
            is_public: For INPUT gates, whether public.
            name: Name for output wire.
        
        Returns:
            Output wire of the gate.
        """
        output_wire = self._create_wire(name)
        gate = Gate(
            gate_id=self._next_gate_id,
            gate_type=gate_type,
            output=output_wire,
            inputs=inputs or [],
            const_value=const_value,
            is_public=is_public
        )
        self.gates.append(gate)
        self._next_gate_id += 1
        return output_wire
    
    def _create_const(self, value: int, name: Optional[str] = None) -> Wire:
        """
        Create a constant wire.
        
        Args:
            value: Constant value.
            name: Optional wire name.
        
        Returns:
            Wire carrying the constant value.
        """
        return self._create_gate(
            gate_type=GateType.CONST,
            const_value=value,
            name=name
        )
    
    def add_input(
        self,
        is_public: bool = False,
        name: Optional[str] = None
    ) -> Wire:
        """
        Add a single input wire to the circuit.
        
        Args:
            is_public: If True, input is public; if False, it's private (witness).
            name: Optional descriptive name.
        
        Returns:
            Input wire.
        
        Example:
            >>> circuit = ArithmeticCircuit(modulus=97)
            >>> x = circuit.add_input(is_public=False, name="x")
            >>> pub = circuit.add_input(is_public=True, name="statement")
        """
        wire = self._create_gate(
            gate_type=GateType.INPUT,
            is_public=is_public,
            name=name
        )
        self.inputs.append(wire)
        if is_public:
            self.public_inputs.append(wire)
        else:
            self.private_inputs.append(wire)
        return wire
    
    def add_inputs(
        self,
        count: int,
        is_public: bool = False,
        names: Optional[List[str]] = None
    ) -> List[Wire]:
        """
        Add multiple input wires to the circuit.
        
        Args:
            count: Number of inputs to add.
            is_public: If True, all inputs are public.
            names: Optional list of names (must match count).
        
        Returns:
            List of input wires.
        
        Example:
            >>> circuit = ArithmeticCircuit(modulus=97)
            >>> x, y, z = circuit.add_inputs(3, is_public=False)
        """
        if names and len(names) != count:
            raise ValueError(f"Names list length {len(names)} must match count {count}")
        
        wires = []
        for i in range(count):
            name = names[i] if names else None
            wires.append(self.add_input(is_public=is_public, name=name))
        return wires
    
    def add(
        self,
        left: Wire,
        right: Wire,
        name: Optional[str] = None
    ) -> Wire:
        """
        Add an addition gate: out = left + right (mod p).
        
        Args:
            left: Left input wire.
            right: Right input wire.
            name: Optional name for output wire.
        
        Returns:
            Output wire carrying left + right.
        
        Example:
            >>> sum_wire = circuit.add(x, y, name="x_plus_y")
        """
        if left.wire_id not in self.wires or right.wire_id not in self.wires:
            raise ValueError("Input wires must belong to this circuit")
        
        return self._create_gate(
            gate_type=GateType.ADD,
            inputs=[left, right],
            name=name
        )
    
    def mul(
        self,
        left: Wire,
        right: Wire,
        name: Optional[str] = None
    ) -> Wire:
        """
        Add a multiplication gate: out = left * right (mod p).
        
        Args:
            left: Left input wire.
            right: Right input wire.
            name: Optional name for output wire.
        
        Returns:
            Output wire carrying left * right.
        
        Example:
            >>> product_wire = circuit.mul(x, y, name="x_times_y")
        """
        if left.wire_id not in self.wires or right.wire_id not in self.wires:
            raise ValueError("Input wires must belong to this circuit")
        
        return self._create_gate(
            gate_type=GateType.MUL,
            inputs=[left, right],
            name=name
        )
    
    def add_const(self, wire: Wire, constant: int, name: Optional[str] = None) -> Wire:
        """
        Add a constant to a wire: out = wire + constant.
        
        Args:
            wire: Input wire.
            constant: Constant value to add.
            name: Optional output wire name.
        
        Returns:
            Output wire.
        
        Example:
            >>> x_plus_5 = circuit.add_const(x, 5)
        """
        const_wire = self._create_const(constant)
        return self.add(wire, const_wire, name=name)
    
    def mul_const(self, wire: Wire, constant: int, name: Optional[str] = None) -> Wire:
        """
        Multiply a wire by a constant: out = wire * constant.
        
        Args:
            wire: Input wire.
            constant: Constant multiplier.
            name: Optional output wire name.
        
        Returns:
            Output wire.
        
        Example:
            >>> x_times_3 = circuit.mul_const(x, 3)
        """
        const_wire = self._create_const(constant)
        return self.mul(wire, const_wire, name=name)
    
    def set_output(self, *wires: Wire) -> None:
        """
        Mark one or more wires as circuit outputs.
        
        Output wires represent the public statement being proven.
        
        Args:
            *wires: Wires to mark as outputs.
        
        Example:
            >>> circuit.set_output(result)
            >>> circuit.set_output(out1, out2, out3)
        """
        for wire in wires:
            if wire.wire_id not in self.wires:
                raise ValueError(f"Wire {wire} does not belong to this circuit")
            if wire not in self.outputs:
                self.outputs.append(wire)
    
    def evaluate(self, input_values: Dict[Wire, int]) -> Dict[Wire, FiniteField]:
        """
        Evaluate the circuit given an input assignment.
        
        This performs a forward pass through the circuit, computing the value
        on each wire. Used to check circuit satisfiability.
        
        Args:
            input_values: Mapping from input wires to their values (integers).
        
        Returns:
            Mapping from all wires to their computed field element values.
        
        Raises:
            ValueError: If input assignment is incomplete or circuit is unsatisfiable.
        
        Example:
            >>> # Circuit: out = (x + y) * z
            >>> assignment = {x: 3, y: 4, z: 5}
            >>> values = circuit.evaluate(assignment)
            >>> print(values[out].value)  # (3 + 4) * 5 = 35
        """
        # Initialize wire values
        wire_values: Dict[Wire, FiniteField] = {}
        
        # Process gates in order (topological order guaranteed by construction)
        for gate in self.gates:
            if gate.gate_type == GateType.CONST:
                # Constant gate
                wire_values[gate.output] = FiniteField(gate.const_value, self.modulus)
            
            elif gate.gate_type == GateType.INPUT:
                # Input gate - must be provided in input_values
                if gate.output not in input_values:
                    raise ValueError(f"Missing value for input wire {gate.output}")
                wire_values[gate.output] = FiniteField(input_values[gate.output], self.modulus)
            
            elif gate.gate_type == GateType.ADD:
                # Addition gate: out = left + right
                left_val = wire_values.get(gate.inputs[0])
                right_val = wire_values.get(gate.inputs[1])
                if left_val is None or right_val is None:
                    raise ValueError(f"Missing input values for gate {gate}")
                wire_values[gate.output] = left_val + right_val
            
            elif gate.gate_type == GateType.MUL:
                # Multiplication gate: out = left * right
                left_val = wire_values.get(gate.inputs[0])
                right_val = wire_values.get(gate.inputs[1])
                if left_val is None or right_val is None:
                    raise ValueError(f"Missing input values for gate {gate}")
                wire_values[gate.output] = left_val * right_val
        
        return wire_values
    
    def is_satisfied(self, input_values: Dict[Wire, int]) -> bool:
        """
        Check if the circuit is satisfied by the given input assignment.
        
        Args:
            input_values: Assignment of values to input wires.
        
        Returns:
            True if evaluation succeeds without errors, False otherwise.
        
        Example:
            >>> # Check if x=3, y=4, z=5 satisfies circuit
            >>> is_valid = circuit.is_satisfied({x: 3, y: 4, z: 5})
        """
        try:
            self.evaluate(input_values)
            return True
        except (ValueError, KeyError):
            return False
    
    def get_num_gates(self) -> int:
        """Get total number of gates."""
        return len(self.gates)
    
    def get_num_multiplication_gates(self) -> int:
        """
        Get number of multiplication gates.
        
        Important for zk-SNARK complexity, as multiplication gates
        dominate the constraint count.
        """
        return sum(1 for gate in self.gates if gate.gate_type == GateType.MUL)
    
    def get_num_constraints(self) -> int:
        """
        Get number of constraints.
        
        Each multiplication gate typically produces one constraint.
        Addition gates can often be folded into linear combinations.
        """
        return self.get_num_multiplication_gates()
    
    def __repr__(self) -> str:
        return (
            f"ArithmeticCircuit(modulus={self.modulus}, "
            f"gates={self.get_num_gates()}, "
            f"mul_gates={self.get_num_multiplication_gates()}, "
            f"inputs={len(self.inputs)}, "
            f"outputs={len(self.outputs)})"
        )
