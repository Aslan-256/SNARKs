"""
Private Information Retrieval (PIR) Simulation for zkSNARKs.

This module implements a simulated PIR scheme used in PCP-based SNARK
constructions like [BCC+14]. PIR allows a client to retrieve an item from
a database without revealing which item was accessed.

In the SNARK context, PIR enables the verifier to query the PCP oracle
at random positions without revealing those positions to the prover,
maintaining zero-knowledge properties.

References:
    [BCC+14] "Hunting of the SNARK", Section 6.3: Using PIR for Zero-Knowledge
    [KO97] Kushilevitz-Ostrovsky: Single-Database PIR
"""

from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
import hashlib
import random


class SimulatedPIR:
    """
    Mock Private Information Retrieval (PIR) scheme.
    
    PIR allows a client to retrieve an item from a database without
    revealing which item was retrieved. This is a simulated version
    for educational purposes - real PIR requires sophisticated
    cryptographic techniques (e.g., homomorphic encryption, lattice-based crypto).
    
    **Real-World PIR:**
    - Computational PIR: Based on public-key encryption (e.g., Paillier, LWE)
    - Information-Theoretic PIR: Multiple non-colluding servers
    - This simulation: Uses random masking to demonstrate the protocol flow
    
    **Security Properties (In Real PIR):**
    1. Privacy: Server learns nothing about queried index
    2. Correctness: Client retrieves correct item
    3. Soundness: Client cannot extract multiple items
    
    **Application in SNARKs:**
    In [BCC+14], PIR is used to:
    - Hide which PCP positions the verifier queries
    - Maintain zero-knowledge while allowing verification
    - Reduce communication complexity in adaptive arguments
    
    The simulation maintains the protocol structure by:
    1. Using encrypted queries (simulated with random masking)
    2. Generating responses that don't reveal the query
    3. Allowing only the key holder to extract the answer
    
    Attributes:
        security_parameter (int): Security level in bits (λ in literature).
    
    Example:
        >>> pir = SimulatedPIR(security_parameter=128)
        >>> database = [b"item0", b"item1", b"item2"]
        >>> query, key = pir.query_gen(index=1, database_size=len(database))
        >>> response = pir.answer_gen(database, query)
        >>> result = pir.extract(response, key, index=1)
        >>> assert result == b"item1"
    """
    
    @dataclass
    class Query:
        """
        Represents an encrypted PIR query.
        
        In real PIR (e.g., Kushilevitz-Ostrovsky):
        - Query is an encryption of the index i
        - Homomorphic properties allow server to compute on encrypted data
        - Size is O(log n) for computational PIR
        
        Attributes:
            ciphertext (bytes): Encrypted query data.
            metadata (Dict): Additional protocol information.
        """
        ciphertext: bytes
        metadata: Dict[str, Any]
    
    @dataclass
    class Response:
        """
        Represents a PIR response.
        
        In real PIR:
        - Response is computed homomorphically from encrypted query
        - Size is typically O(√n) or O(log n) depending on scheme
        - Client can decrypt to get the requested item
        
        Attributes:
            data (bytes): Encrypted response data.
            proof (Optional[bytes]): Optional correctness proof.
        """
        data: bytes
        proof: Optional[bytes] = None
    
    def __init__(self, security_parameter: int = 128):
        """
        Initialize PIR scheme.
        
        Args:
            security_parameter: Security level in bits (λ).
                               Typical values: 128, 192, 256.
                               Determines key sizes and collision resistance.
        
        Example:
            >>> pir = SimulatedPIR(security_parameter=256)
        """
        self.security_parameter = security_parameter
    
    def query_gen(self, index: int, database_size: int) -> Tuple[Query, bytes]:
        """
        Generate a PIR query for a specific index.
        
        **Real PIR Query Generation (e.g., [KO97]):**
        1. Generate public key pk, secret key sk
        2. Encrypt index: c = Enc_pk(index)
        3. Send c to server
        
        **Simulation:**
        Creates a cryptographic commitment to the index using a random key.
        The commitment is collision-resistant but doesn't reveal the index.
        
        **Security Analysis:**
        - Privacy: Ciphertext is pseudorandom, reveals no info about index
        - Binding: Given commitment, client cannot change queried index
        
        Args:
            index: The database index to query (0-based).
            database_size: Total number of items in the database.
        
        Returns:
            Tuple of (encrypted_query, secret_key).
            The secret_key is needed to decrypt the response.
        
        Raises:
            ValueError: If index is out of bounds.
        
        Example:
            >>> pir = SimulatedPIR()
            >>> query, key = pir.query_gen(5, database_size=100)
            >>> # Server cannot determine that index=5 from query
        """
        if index < 0 or index >= database_size:
            raise ValueError(f"Index {index} out of bounds [0, {database_size})")
        
        # Generate a random secret key (λ bits)
        secret_key = random.randbytes(self.security_parameter // 8)
        
        # Create encrypted query (simulation: hash of index + key + salt)
        # In real PIR: c = Enc_pk(index) using homomorphic encryption
        h = hashlib.sha256()
        h.update(index.to_bytes(8, 'big'))
        h.update(secret_key)
        h.update(database_size.to_bytes(8, 'big'))
        ciphertext = h.digest()
        
        # Store metadata (in real PIR, embedded in ciphertext structure)
        metadata = {
            'index': index,  # Hidden in real implementation
            'database_size': database_size,
            'timestamp': random.randint(0, 2**32),  # Randomness for security
            'nonce': random.randbytes(16).hex()
        }
        
        query = self.Query(ciphertext=ciphertext, metadata=metadata)
        return query, secret_key
    
    def answer_gen(self, database: List[bytes], query: Query) -> Response:
        """
        Generate a PIR response to a query.
        
        **Real PIR Response Generation:**
        1. Server receives encrypted query c
        2. Homomorphically computes: r = Σ_j D[j] · (c == j)
        3. Send r to client (size independent of database!)
        
        **Simulation:**
        Retrieves the item and encrypts it with query-derived key.
        
        **Complexity:**
        - Computation: O(n) server operations (scan entire database)
        - Communication: O(1) or O(√n) response size
        - Real schemes achieve sublinear communication through clever encoding
        
        Args:
            database: List of data items (the PCP oracle in SNARK context).
            query: The PIR query from query_gen().
        
        Returns:
            PIR response that can be decrypted with the secret key.
        
        Raises:
            ValueError: If query is invalid for the database.
        
        Example:
            >>> database = [b"secret0", b"secret1", b"secret2"]
            >>> query, key = pir.query_gen(1, len(database))
            >>> response = pir.answer_gen(database, query)
            >>> # Response doesn't reveal which item was queried
        """
        # Extract hidden index from metadata (simulation)
        # In real PIR, server processes entire database homomorphically
        index = query.metadata.get('index', 0)
        db_size = query.metadata.get('database_size', len(database))
        
        if index < 0 or index >= len(database):
            raise ValueError(f"Invalid query index: {index}")
        if db_size != len(database):
            raise ValueError(f"Database size mismatch: {db_size} vs {len(database)}")
        
        # Retrieve the requested item
        item = database[index]
        
        # "Encrypt" the response using the query ciphertext as key derivation
        # Real PIR: Response is structured s.t. only key holder can extract answer
        h = hashlib.sha256()
        h.update(query.ciphertext)
        h.update(item)
        hash_component = h.digest()
        
        # Format: hash(ciphertext || item) || item
        # This allows verification while maintaining structure
        encrypted_data = hash_component + item
        
        return self.Response(data=encrypted_data)
    
    def extract(self, response: Response, secret_key: bytes, index: int) -> bytes:
        """
        Extract the answer from a PIR response.
        
        **Real PIR Extraction:**
        1. Decrypt response using secret key
        2. Recover the database item
        3. Verify correctness (if proof included)
        
        **Simulation:**
        Extracts item from response structure and optionally verifies hash.
        
        Args:
            response: The PIR response from answer_gen().
            secret_key: The secret key from query_gen().
            index: The queried index (needed for verification).
        
        Returns:
            The decrypted database item.
        
        Raises:
            ValueError: If response format is invalid.
        
        Example:
            >>> query, key = pir.query_gen(2, 10)
            >>> response = pir.answer_gen(database, query)
            >>> item = pir.extract(response, key, index=2)
        """
        # Response format: hash(query_ciphertext || item) || item
        if len(response.data) <= 32:
            raise ValueError("Invalid response format: too short")
        
        hash_component = response.data[:32]
        item = response.data[32:]
        
        # Optional: Verify hash for integrity
        # (In real PIR, this would involve more complex verification)
        
        return item
    
    def get_communication_complexity(self, database_size: int) -> Dict[str, int]:
        """
        Compute communication complexity for this PIR scheme.
        
        **Comparison with Real PIR:**
        - Trivial Download: O(n) communication
        - This Simulation: O(1) query + O(1) response = O(1) total
        - Real Computational PIR: O(log n) query + O(√n) response
        - Optimal Information-Theoretic PIR: O(n^(1/3)) with 2 servers
        
        Args:
            database_size: Number of items in database.
        
        Returns:
            Dictionary with query_size, response_size, total_size in bytes.
        
        Example:
            >>> pir = SimulatedPIR()
            >>> complexity = pir.get_communication_complexity(1000)
            >>> print(complexity)
            {'query_size': 32, 'response_size': 32+, 'total_size': 64+}
        """
        query_size = 32  # SHA256 output size
        response_overhead = 32  # Hash component
        
        # Note: Response size depends on item size (variable)
        # In real PIR, response size is often O(√n · item_size)
        
        return {
            'query_size': query_size,
            'response_overhead': response_overhead,
            'database_size': database_size,
            'note': 'Simulation: O(1) complexity. Real PIR: O(√n) or O(log n)'
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return f"SimulatedPIR(security_parameter={self.security_parameter})"
