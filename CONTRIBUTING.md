# Contributing to AI Agents in Cybersecurity

First off, thank you for considering contributing to this project! It's people like you that make this a great resource for the cybersecurity community.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@aiagentscybersecurity.com.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps to reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed and what behavior you expected
* Include screenshots if relevant
* Include your environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* A clear and descriptive title
* A detailed description of the proposed enhancement
* Explain why this enhancement would be useful
* List any similar features in other projects

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure the test suite passes
4. Make sure your code follows the style guidelines
5. Issue that pull request!

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/ai-agents-cybersecurity.git
cd ai-agents-cybersecurity

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

## Style Guidelines

### Python Style Guide

We use Black for code formatting and follow PEP 8:

```bash
# Format your code
black .

# Check linting
flake8 .

# Type checking
mypy .
```

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

Example:
```
Add SOAR integration for ServiceNow

- Implement webhook handler for incident creation
- Add authentication module for OAuth2
- Include retry logic for API failures

Fixes #123
```

### Documentation

* Use Markdown for documentation
* Include docstrings for all public functions
* Update README.md if you change functionality
* Add examples for new features

### Testing

* Write unit tests for new functionality
* Ensure all tests pass before submitting PR
* Aim for >80% code coverage
* Include integration tests for API changes

## Project Structure

When adding new features, follow the existing structure:

```
chapter-examples/chXX-topic/
├── README.md           # Explain the feature
├── __init__.py        # Module initialization
├── core.py            # Core implementation
├── config.py          # Configuration
├── tests/             # Test files
│   ├── test_core.py
│   └── test_integration.py
└── examples/          # Usage examples
```

## Security Considerations

* Never commit secrets or API keys
* Use environment variables for configuration
* Validate all inputs
* Follow OWASP secure coding practices
* Report security vulnerabilities privately to security@aiagentscybersecurity.com

## Code Review Process

All submissions require review before merging:

1. Automated checks must pass (tests, linting, security scan)
2. At least one maintainer approval required
3. No merge conflicts with main branch
4. Documentation updated if needed

## Community

* Join our [Discord server](https://discord.gg/aiagentscyber)
* Follow us on [Twitter](https://twitter.com/aiagentscyber)
* Read our [blog](https://blog.aiagentscybersecurity.com)
* Attend our monthly community calls

## Recognition

Contributors will be recognized in:
* The AUTHORS.md file
* Release notes
* The book's acknowledgments (major contributors)

## Questions?

Feel free to open an issue with the label "question" or reach out on Discord.

Thank you for contributing! 🎉