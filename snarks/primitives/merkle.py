"""
Merkle Tree Implementation for zkSNARKs.

This module implements Squashed Merkle Trees with configurable fan-in (arity),
a key optimization in modern SNARK constructions like [BCC+14].

Unlike standard binary Merkle trees, squashed trees support arbitrary arity
to reduce tree depth, which is critical for reducing extraction complexity
in PCP-based SNARKs.

References:
    [BCC+14] "Hunting of the SNARK" - Bitansky, Chiesa, Canetti, Tromer
    Section 6: SNARKs from PCP - Using Extractable Collision-Resistant Hashing
"""

from typing import List, Tuple
import hashlib


class MerkleTree:
    """
    Squashed Merkle Tree with configurable fan-in (arity).
    
    Unlike standard binary Merkle trees, this implementation supports
    arbitrary arity to reduce tree depth - a key optimization in the
    [BCC+14] construction for reducing extraction complexity.
    
    The tree uses SHA256 as the collision-resistant hash function,
    which acts as an Extractable Collision-Resistant Hash (ECRH) in
    the theoretical framework.
    
    **Mathematical Foundation:**
    For a tree with n leaves and arity k:
    - Depth: d = ⌈log_k(n)⌉
    - Total nodes: ≤ n · (k/(k-1))
    - Auth path size: O(k · log_k(n))
    
    **Security Properties:**
    - Collision Resistance: Finding x ≠ y with H(x) = H(y) is computationally hard
    - Extractability: In the ECRH model, the extractor can recover preimages
    
    Attributes:
        arity (int): Number of children per node (fan-in).
        leaves (List[bytes]): The leaf data.
        tree (List[List[bytes]]): The complete tree structure (level by level).
        root (bytes): The Merkle root hash.
    
    Example:
        >>> data = [b"leaf0", b"leaf1", b"leaf2", b"leaf3"]
        >>> mt = MerkleTree(data, arity=2)
        >>> path = mt.get_authentication_path(1)
        >>> is_valid = mt.verify_authentication_path(1, b"leaf1", path)
    """
    
    def __init__(self, data: List[bytes], arity: int = 2):
        """
        Initialize a Squashed Merkle Tree.
        
        Args:
            data: List of byte strings to store as leaves.
            arity: Fan-in parameter (default: 2 for binary tree).
                  Higher arity reduces depth at the cost of larger nodes.
                  Typical values: 2 (binary), 4, 8, 16.
        
        Raises:
            ValueError: If data is empty or arity < 2.
        
        Example:
            >>> mt = MerkleTree([b"a", b"b", b"c"], arity=2)
            >>> print(mt.root.hex()[:16])  # First 16 chars of root hash
        """
        if not data:
            raise ValueError("Cannot create Merkle tree with empty data")
        if arity < 2:
            raise ValueError("Arity must be at least 2")
        
        self.arity = arity
        self.leaves = data
        self.tree = self._build_tree()
        self.root = self.tree[-1][0]  # Root is the single node at the top level
    
    def _hash(self, *items: bytes) -> bytes:
        """
        Hash multiple items together using SHA256.
        
        This implements the collision-resistant hash function H used
        throughout the Merkle tree construction.
        
        Args:
            *items: Variable number of byte strings to hash together.
        
        Returns:
            32-byte SHA256 digest.
        """
        h = hashlib.sha256()
        for item in items:
            h.update(item)
        return h.digest()
    
    def _build_tree(self) -> List[List[bytes]]:
        """
        Build the Merkle tree bottom-up.
        
        **Algorithm:**
        1. Start with leaves as level 0
        2. For each level:
           - Group nodes into chunks of size 'arity'
           - Hash each chunk to create parent node
           - Pad incomplete chunks with last child
        3. Repeat until single root node remains
        
        **Complexity:**
        - Time: O(n) where n is number of leaves
        - Space: O(n · k/(k-1)) for storing full tree
        
        Returns:
            List of levels, where level[0] is leaves and level[-1] is root.
        
        Note:
            Padding strategy: Incomplete groups are padded by repeating
            the last child. This maintains security while avoiding dummy nodes.
        """
        levels = [self.leaves[:]]  # Start with leaves
        current_level = self.leaves[:]
        
        # Build tree level by level until we reach a single root
        while len(current_level) > 1:
            next_level = []
            
            # Process nodes in groups of 'arity'
            for i in range(0, len(current_level), self.arity):
                # Get up to 'arity' children
                children = current_level[i:i + self.arity]
                
                # Pad with the last child if needed (for incomplete groups)
                while len(children) < self.arity and len(children) > 0:
                    children.append(children[-1])
                
                # Hash all children together to form parent
                parent = self._hash(*children) 
                next_level.append(parent)
            
            levels.append(next_level)
            current_level = next_level
        
        return levels
    
    def get_authentication_path(self, leaf_index: int) -> List[Tuple[int, List[bytes]]]:
        """
        Generate authentication path (Merkle proof) for a leaf.
        
        The authentication path allows verification that a leaf is part
        of the committed tree without revealing the entire tree. This is
        crucial for succinctness in SNARK constructions.
        
        **Protocol:**
        1. Start at the leaf node
        2. For each level going up to root:
           - Record position within sibling group
           - Include all siblings needed for hash computation
        3. Return path as list of (position, siblings) tuples
        
        **Communication Complexity:**
        - Path length: O(k · log_k(n)) bytes
        - Number of rounds: log_k(n)
        
        Args:
            leaf_index: Index of the leaf to prove (0-based).
        
        Returns:
            List of (position, siblings) tuples representing the path from
            leaf to root. Each tuple contains:
                - position: Node's position in its sibling group (0 to arity-1)
                - siblings: All arity nodes in the group for hash verification
        
        Raises:
            IndexError: If leaf_index is out of bounds.
        
        Example:
            >>> mt = MerkleTree([b"a", b"b", b"c", b"d"], arity=2)
            >>> path = mt.get_authentication_path(1)
            >>> # Path contains siblings at each level for verifying leaf 1
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of bounds [0, {len(self.leaves)})")
        
        path = []
        current_index = leaf_index
        
        # Traverse from leaf to root
        for level_idx in range(len(self.tree) - 1):
            level = self.tree[level_idx]
            
            # Determine which group (of arity nodes) this node belongs to
            group_start = (current_index // self.arity) * self.arity
            group_end = min(group_start + self.arity, len(level))
            
            # Position within the group (0 to arity-1)
            position_in_group = current_index - group_start
            
            # Get all siblings in the group
            siblings = level[group_start:group_end]
            
            # Pad if group is incomplete (maintain consistency with tree building)
            while len(siblings) < self.arity:
                siblings.append(siblings[-1])
            
            path.append((position_in_group, siblings))
            
            # Move to parent in next level
            current_index = current_index // self.arity
            
            # Visual representation for arity=2:
            # Level 2:                [Root](0)
            #                        /          \
            # Level 1:          [P1](0)          [P2](1)
            #                   /      \         /      \
            # Level 0:      [L0](0)  [L1](1)  [L2](2)  [L3](3)
            #
            # For leaf_index=1: current_index updates as 1→0→0 (parent indices)
        
        return path
    
    def verify_authentication_path(
        self,
        leaf_index: int,
        leaf_data: bytes,
        path: List[Tuple[int, List[bytes]]]
    ) -> bool:
        """
        Verify an authentication path against the Merkle root.
        
        This is the verification algorithm used by the SNARK verifier
        to check that a committed value is part of the Merkle tree.
        
        **Verification Algorithm:**
        1. Start with leaf_data as current hash
        2. For each level in the path:
           - Verify current hash matches sibling at expected position
           - Recompute parent hash from all siblings
           - Move up to next level
        3. Check final hash equals root
        
        **Security:**
        Soundness relies on collision resistance of SHA256. An adversary
        cannot create a valid path for data not in the tree without breaking
        the hash function.
        
        Args:
            leaf_index: Index of the leaf being verified.
            leaf_data: The actual leaf data to verify.
            path: Authentication path from get_authentication_path().
        
        Returns:
            True if the path is valid and leaf_data is committed, False otherwise.
        
        Example:
            >>> mt = MerkleTree([b"a", b"b", b"c"], arity=2)
            >>> path = mt.get_authentication_path(1)
            >>> mt.verify_authentication_path(1, b"b", path)
            True
            >>> mt.verify_authentication_path(1, b"wrong", path)
            False
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            return False
        
        # Start with the leaf data
        current_hash = leaf_data
        current_index = leaf_index
        
        # Verify each level of the path
        for level_idx, (position, siblings) in enumerate(path):
            # Verify position is valid
            if position >= len(siblings) or position >= self.arity:
                return False
            
            # Verify current hash matches the claimed sibling position
            if current_hash != siblings[position]:
                return False
            
            # Recompute parent hash from all siblings
            current_hash = self._hash(*siblings)
            
            # Move to parent index
            current_index = current_index // self.arity
        
        # Final hash should match the root
        return current_hash == self.root
    
    def get_depth(self) -> int:
        """
        Get the depth of the Merkle tree.
        
        Returns:
            Number of levels from leaves to root.
        """
        return len(self.tree) - 1
    
    def __repr__(self) -> str:
        """String representation of the Merkle tree."""
        return (
            f"MerkleTree(leaves={len(self.leaves)}, "
            f"arity={self.arity}, "
            f"depth={self.get_depth()}, "
            f"root={self.root.hex()[:16]}...)"
        )
