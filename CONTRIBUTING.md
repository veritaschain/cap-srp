# Contributing to CAP-SRP

Thank you for your interest in contributing to CAP-SRP! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, etc.)
- **Relevant logs or error messages**

### Suggesting Features

Feature requests are welcome! Please:

1. Check existing issues/discussions for similar requests
2. Describe the use case clearly
3. Explain how it aligns with CAP-SRP's goals
4. Consider security and privacy implications

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow code style** guidelines (see below)
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Ensure all tests pass** before submitting

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cap-srp-dashboard.git
cd cap-srp-dashboard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Code Style

We use:

- **Black** for code formatting
- **isort** for import sorting
- **Ruff** for linting
- **mypy** for type checking

Run checks locally:

```bash
# Format code
black cap_srp tests
isort cap_srp tests

# Lint
ruff check cap_srp tests

# Type check
mypy cap_srp
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=cap_srp --cov-report=html

# Run specific test file
pytest tests/test_verifier.py -v
```

## Documentation

- Use Google-style docstrings
- Update README.md for user-facing changes
- Add inline comments for complex logic

Example docstring:

```python
def verify_completeness(events: List[CAPEvent]) -> CompletenessResult:
    """
    Verify the Completeness Invariant for a list of events.
    
    The Completeness Invariant ensures that:
        Σ ATTEMPTS = Σ GEN + Σ DENY + Σ ERROR
    
    Args:
        events: List of CAP events to verify
        
    Returns:
        CompletenessResult: Detailed verification result
        
    Raises:
        ValueError: If events list contains invalid event types
        
    Example:
        >>> verifier = CompletenessVerifier()
        >>> result = verifier.verify(events)
        >>> print(f"Valid: {result.is_valid}")
    """
```

## Security Considerations

CAP-SRP is security-critical software. When contributing:

1. **Never commit secrets** (keys, tokens, etc.)
2. **Review cryptographic changes** carefully
3. **Consider attack vectors** in new features
4. **Follow principle of least privilege**
5. **Report security issues privately** to security@veritaschain.org

## Release Process

1. Update version in `pyproject.toml` and `cap_srp/__init__.py`
2. Update `CHANGELOG.md`
3. Create a tagged release
4. CI automatically publishes to PyPI

## Questions?

- **Email**: developers@veritaschain.org
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
