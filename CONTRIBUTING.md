# Contributing to SNARKs

Thank you for your interest in contributing to this educational zero-knowledge proof systems project! 

## Project Goals

This project aims to:
1. Provide clear, educational implementations of fundamental zk-SNARK concepts
2. Help students and researchers understand zero-knowledge proof theory
3. Serve as a reference implementation for academic study
4. Maintain clean, well-documented code with strong pedagogical value

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Your Python version and OS

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:
- Check if the enhancement aligns with educational goals
- Provide a clear use case
- Consider whether it improves understanding of the concepts

### Code Contributions

#### Setup Development Environment

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/SNARKs.git
cd SNARKs

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install development dependencies
pip install pytest pytest-benchmark black mypy
```

#### Development Workflow

1. **Create a branch**: `git checkout -b feature/your-feature-name`
2. **Make changes**: Follow our coding standards (see below)
3. **Add tests**: All new code should have tests
4. **Run tests**: `pytest snarks/tests/ -v`
5. **Update docs**: Update README.md and docstrings as needed
6. **Commit**: Use clear, descriptive commit messages
7. **Push**: `git push origin feature/your-feature-name`
8. **Create PR**: Open a pull request with a clear description

#### Coding Standards

**Python Style**
- Follow PEP 8 guidelines
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Use meaningful variable names

**Type Hints**
- Add type hints to all function signatures
- Use `typing` module for complex types

**Docstrings**
- Use Google-style docstrings
- Document all public functions, classes, and methods
- Include examples in docstrings where helpful

**Example:**
```python
def example_function(value: int, modulus: int) -> FiniteField:
    """
    Create a finite field element.
    
    Args:
        value: The integer value to represent.
        modulus: The prime modulus of the field.
    
    Returns:
        A FiniteField instance.
    
    Raises:
        ValueError: If modulus is not positive.
    
    Example:
        >>> elem = example_function(5, 7)
        >>> print(elem)
        5 (mod 7)
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive")
    return FiniteField(value, modulus)
```

**Testing**
- Write unit tests for all new functionality
- Aim for high test coverage
- Use descriptive test names: `test_addition_with_different_fields_raises_error`
- Include edge cases and error conditions

**Example Test:**
```python
def test_field_addition():
    """Test that field addition works correctly."""
    a = FiniteField(5, 7)
    b = FiniteField(3, 7)
    result = a + b
    assert result.value == 1  # (5 + 3) mod 7 = 1
```

#### Code Review Process

1. All submissions require review
2. Reviewers will check:
   - Code quality and style
   - Test coverage
   - Documentation completeness
   - Educational value
3. Address review comments promptly
4. Be open to suggestions and learning

### Areas for Contribution

Here are some areas where contributions are especially welcome:

#### Documentation
- Improve theoretical explanations
- Add more examples
- Create tutorials or blog posts
- Fix typos or clarify confusing sections

#### Testing
- Add edge case tests
- Improve test coverage
- Add performance tests
- Add integration tests

#### Features
- Implement additional proof systems
- Add visualization tools
- Create interactive notebooks
- Improve benchmarking

#### Code Quality
- Refactor for clarity
- Optimize algorithms (while maintaining readability)
- Improve error messages
- Add better logging

## Style Guidelines

### Commit Messages
```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem this commit solves and how.

- Use bullet points for multiple changes
- Reference issues: Fixes #123
```

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Testing
- [ ] All tests pass
- [ ] New tests added
- [ ] Documentation updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added to complex code
- [ ] Documentation updated
```

## Educational Focus

Remember that this is an **educational project**. When contributing:

1. **Clarity over efficiency**: Readable code is more important than micro-optimizations
2. **Explain the "why"**: Add comments explaining the theory, not just the code
3. **Concrete examples**: Include examples in documentation
4. **Mathematical correctness**: Ensure implementations align with theory
5. **Avoid premature optimization**: Keep it simple and understandable

## Questions?

If you have questions about contributing:
- Open an issue for discussion
- Check existing issues and PRs
- Review the README.md for project context

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make zero-knowledge proofs more accessible to learners! 🎓
