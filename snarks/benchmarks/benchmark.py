"""
Benchmark suite for all proof systems.

This module provides performance benchmarks for setup, prove, and verify
operations across all implemented proof systems.
"""

import time
from typing import Dict, List, Tuple, Callable
from snarks.proofs.pcp import PCP
from snarks.proofs.qap import QAP
from snarks.proofs.lip import LIP
from snarks.proofs.piop import PIOP


class BenchmarkResult:
    """Stores benchmark results."""
    
    def __init__(self, name: str, setup_time: float, prove_time: float, 
                 verify_time: float, iterations: int = 1):
        """
        Initialize benchmark result.
        
        Args:
            name: Name of the benchmark.
            setup_time: Time taken for setup (seconds).
            prove_time: Time taken for proving (seconds).
            verify_time: Time taken for verification (seconds).
            iterations: Number of iterations run.
        """
        self.name = name
        self.setup_time = setup_time
        self.prove_time = prove_time
        self.verify_time = verify_time
        self.iterations = iterations
        self.avg_setup = setup_time / iterations
        self.avg_prove = prove_time / iterations
        self.avg_verify = verify_time / iterations
        self.total_time = setup_time + prove_time + verify_time
    
    def __str__(self) -> str:
        """Format results as string."""
        return (f"{self.name}:\n"
                f"  Setup:  {self.avg_setup*1000:.3f} ms (total: {self.setup_time*1000:.3f} ms)\n"
                f"  Prove:  {self.avg_prove*1000:.3f} ms (total: {self.prove_time*1000:.3f} ms)\n"
                f"  Verify: {self.avg_verify*1000:.3f} ms (total: {self.verify_time*1000:.3f} ms)\n"
                f"  Total:  {self.total_time*1000:.3f} ms ({self.iterations} iterations)")


def benchmark_system(name: str, setup_fn: Callable, prove_fn: Callable,
                    verify_fn: Callable, iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark a proof system.
    
    Args:
        name: Name of the system.
        setup_fn: Function that returns setup parameters.
        prove_fn: Function that takes setup and returns (proof, witness, statement).
        verify_fn: Function that takes (setup, proof, witness, statement) and verifies.
        iterations: Number of iterations to run.
    
    Returns:
        BenchmarkResult containing timing information.
    """
    # Benchmark setup
    setup_start = time.time()
    for _ in range(iterations):
        setup = setup_fn()
    setup_time = time.time() - setup_start
    
    # Get setup for prove/verify benchmarks
    setup = setup_fn()
    
    # Benchmark prove
    prove_start = time.time()
    proofs = []
    for _ in range(iterations):
        proof, witness, statement = prove_fn(setup)
        proofs.append((proof, witness, statement))
    prove_time = time.time() - prove_start
    
    # Benchmark verify
    verify_start = time.time()
    for proof, witness, statement in proofs:
        verify_fn(setup, proof, witness, statement)
    verify_time = time.time() - verify_start
    
    return BenchmarkResult(name, setup_time, prove_time, verify_time, iterations)


def benchmark_pcp(modulus: int = 97, iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark PCP system.
    
    Args:
        modulus: Field modulus.
        iterations: Number of iterations.
    
    Returns:
        BenchmarkResult for PCP.
    """
    def setup_fn():
        return PCP.setup(modulus=modulus)
    
    def prove_fn(setup):
        witness = [3, 4, 5]
        statement = [12]
        proof = PCP.prove(setup, witness, statement)
        return proof, witness, statement
    
    def verify_fn(setup, proof, witness, statement):
        return PCP.verify(setup, proof, statement)
    
    return benchmark_system("PCP", setup_fn, prove_fn, verify_fn, iterations)


def benchmark_qap(modulus: int = 97, iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark QAP system.
    
    Args:
        modulus: Field modulus.
        iterations: Number of iterations.
    
    Returns:
        BenchmarkResult for QAP.
    """
    def setup_fn():
        return QAP.setup(modulus=modulus)
    
    def prove_fn(setup):
        witness = [1, 3, 4, 12]
        statement = [1, 12]
        proof = QAP.prove(setup, witness)
        return proof, witness, statement
    
    def verify_fn(setup, proof, witness, statement):
        return QAP.verify(setup, proof, statement)
    
    return benchmark_system("QAP", setup_fn, prove_fn, verify_fn, iterations)


def benchmark_lip(modulus: int = 97, iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark LIP system.
    
    Args:
        modulus: Field modulus.
        iterations: Number of iterations.
    
    Returns:
        BenchmarkResult for LIP.
    """
    def setup_fn():
        return LIP.setup(modulus=modulus, num_variables=3, num_rounds=2)
    
    def prove_fn(setup):
        witness = [3, 4, 5]
        statement = [12]
        proof, _ = LIP.interactive_prove_verify(setup, witness, statement)
        return proof, witness, statement
    
    def verify_fn(setup, proof, witness, statement):
        return LIP.verify(setup, proof, statement)
    
    return benchmark_system("LIP", setup_fn, prove_fn, verify_fn, iterations)


def benchmark_piop(modulus: int = 97, iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark PIOP system.
    
    Args:
        modulus: Field modulus.
        iterations: Number of iterations.
    
    Returns:
        BenchmarkResult for PIOP.
    """
    def setup_fn():
        return PIOP.setup(modulus=modulus, num_variables=3, poly_degree=3)
    
    def prove_fn(setup):
        witness = [3, 4, 5]
        statement = [60]
        proof = PIOP.prove(setup, witness, statement)
        return proof, witness, statement
    
    def verify_fn(setup, proof, witness, statement):
        return PIOP.verify(setup, proof, statement, num_queries=3)
    
    return benchmark_system("PIOP", setup_fn, prove_fn, verify_fn, iterations)


def run_all_benchmarks(iterations: int = 100, modulus: int = 97) -> Dict[str, BenchmarkResult]:
    """
    Run benchmarks for all proof systems.
    
    Args:
        iterations: Number of iterations for each benchmark.
        modulus: Field modulus to use.
    
    Returns:
        Dictionary mapping system names to benchmark results.
    """
    print(f"\nRunning benchmarks with {iterations} iterations...")
    print(f"Field modulus: {modulus}")
    print("="*70)
    
    results = {}
    
    print("\nBenchmarking PCP...")
    results['PCP'] = benchmark_pcp(modulus, iterations)
    print(results['PCP'])
    
    print("\nBenchmarking QAP...")
    results['QAP'] = benchmark_qap(modulus, iterations)
    print(results['QAP'])
    
    print("\nBenchmarking LIP...")
    results['LIP'] = benchmark_lip(modulus, iterations)
    print(results['LIP'])
    
    print("\nBenchmarking PIOP...")
    results['PIOP'] = benchmark_piop(modulus, iterations)
    print(results['PIOP'])
    
    return results


def print_summary(results: Dict[str, BenchmarkResult]):
    """
    Print benchmark summary table.
    
    Args:
        results: Dictionary of benchmark results.
    """
    print("\n" + "="*70)
    print("Benchmark Summary (Average per iteration)")
    print("="*70)
    print(f"{'System':<10} {'Setup (ms)':<15} {'Prove (ms)':<15} {'Verify (ms)':<15}")
    print("-"*70)
    
    for name, result in results.items():
        print(f"{name:<10} {result.avg_setup*1000:<15.3f} "
              f"{result.avg_prove*1000:<15.3f} {result.avg_verify*1000:<15.3f}")
    
    print("="*70 + "\n")


def main():
    """Run all benchmarks and display results."""
    results = run_all_benchmarks(iterations=100, modulus=97)
    print_summary(results)


if __name__ == "__main__":
    main()
