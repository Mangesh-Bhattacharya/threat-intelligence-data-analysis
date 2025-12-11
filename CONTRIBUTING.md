# Contributing to Threat Intelligence Platform

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Use the bug report template
3. Include detailed steps to reproduce
4. Provide system information and logs

### Suggesting Features

1. Check existing feature requests
2. Clearly describe the feature and its benefits
3. Provide use cases and examples

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write/update tests
5. Ensure all tests pass
6. Update documentation
7. Commit with clear messages
8. Push to your fork
9. Open a Pull Request

## Development Setup

```bash
# Clone repository
git clone https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis.git
cd threat-intelligence-data-analysis

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Run linting
flake8 app/ utils/
black app/ utils/
```

## Coding Standards

### Python Style Guide

- Follow PEP 8
- Use type hints
- Write docstrings for all functions/classes
- Maximum line length: 100 characters
- Use meaningful variable names

### Example

```python
def analyze_threat(data: pd.DataFrame, threshold: float = 0.8) -> Dict[str, Any]:
    """
    Analyze threat data and return results.
    
    Args:
        data: DataFrame containing threat data
        threshold: Confidence threshold for detection
    
    Returns:
        Dictionary with analysis results
    """
    # Implementation
    pass
```

### Testing

- Write unit tests for new features
- Maintain >80% code coverage
- Use pytest fixtures
- Test edge cases and error handling

### Documentation

- Update README.md for major changes
- Add docstrings to all public functions
- Include code examples
- Update API documentation

## Security

- Never commit secrets or credentials
- Use environment variables for sensitive data
- Follow OWASP security guidelines
- Report security vulnerabilities privately

## Commit Messages

Use clear, descriptive commit messages:

```
feat: Add anomaly detection algorithm
fix: Resolve memory leak in data processor
docs: Update installation instructions
test: Add tests for threat classifier
refactor: Optimize database queries
```

## Review Process

1. All PRs require review
2. Address review comments
3. Ensure CI/CD passes
4. Maintain code quality standards

## Questions?

Open an issue or contact: mangesh.bhattacharya@ontariotechu.net

Thank you for contributing! 🎉
