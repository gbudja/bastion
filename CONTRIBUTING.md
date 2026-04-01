# Contributing to Bastion

Thank you for your interest in contributing to Bastion! This document provides guidelines
and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/bastion.git`
3. Create a virtual environment: `python3 -m venv venv && source venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Create a feature branch: `git checkout -b feature/your-feature`

## Development Workflow

### Running in Demo Mode

```bash
bastion start --demo
```

This runs Bastion without needing root or nftables — perfect for development.

### Running Tests

```bash
pytest tests/ -v --cov=bastion
```

### Code Quality

We use these tools to maintain code quality:

```bash
# Format code
black bastion/ tests/

# Lint
ruff check bastion/ tests/

# Type checking
mypy bastion/
```

### Pre-commit Hooks

```bash
pre-commit install
```

## Pull Request Process

1. Update tests for any new functionality
2. Ensure all tests pass and linting is clean
3. Update documentation if needed
4. Write a clear PR description explaining the change
5. Reference any related issues

## Code Style

- Follow PEP 8 (enforced by black and ruff)
- Use type hints for all function signatures
- Write docstrings for all public classes and methods
- Keep functions focused and under 50 lines where possible

## Architecture Guidelines

- **Models** belong in `bastion/core/models.py`
- **Backend logic** (nftables interaction) belongs in `bastion/core/engine.py`
- **Business logic** (CRUD, search, validation) belongs in `bastion/core/manager.py`
- **API endpoints** belong in `bastion/api/routes.py`
- **Plugins** get their own module in `bastion/plugins/`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Include your OS, Python version, and Bastion version

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 license.
