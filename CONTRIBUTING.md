# Contributing to Bastion

Thank you for your interest in contributing to Bastion! This document covers how to get started, development workflow, and contribution expectations.

## Getting started

1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/bastion.git
   cd bastion
   ```

2. Create a virtual environment and install dev dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```

## Development workflow

### Running in demo mode

```bash
bastion start --demo
```

Demo mode runs without root or nftables. It generates nft scripts but never applies them. This is the right mode for development on any OS.

### Running tests

```bash
pytest tests/ -v --cov=bastion
```

All tests must pass before submitting a PR. Tests must not require root, network access, or nftables.

### Code quality

```bash
# Lint
ruff check bastion/ tests/

# Format check
black --check bastion/ tests/

# Type checking
mypy bastion/ --ignore-missing-imports
```

Fix any issues before opening a PR. The CI pipeline runs all three checks.

### Pre-commit hooks

```bash
pre-commit install
```

This runs ruff and black automatically on every commit.

## Pull request process

1. Update or add tests for any new functionality.
2. Ensure all tests pass and linting is clean.
3. Update documentation if the change affects user-facing behavior.
4. Write a clear PR description explaining the change and its motivation.
5. Reference any related issues.

## Security contributions

If you find a security issue, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

When contributing code that touches security-sensitive areas:

- **Secrets:** Never hardcode secrets, tokens, or credentials. Use environment variables.
- **Input validation:** Validate all inputs at trust boundaries (API endpoints, file loading, plugin config).
- **Subprocess calls:** All subprocess calls in `engine.py` use `shlex`-quoted args and fixed binary paths — do not introduce shell=True or user-controlled command construction.
- **Plugin loading:** Plugin names are validated against a strict regex before import. Do not relax this.
- **Demo mode vs live mode:** Keep the two modes clearly separated. Demo mode must never execute kernel-level operations.

## Code style

- Follow PEP 8 (enforced by black and ruff)
- Use type hints for all function signatures
- Write docstrings for public classes and methods
- Keep functions focused; prefer clarity over brevity

## Architecture guidelines

| Concern | Location |
| --- | --- |
| Data models | `bastion/core/models.py` |
| nftables interaction | `bastion/core/engine.py` |
| Rule CRUD and business logic | `bastion/core/manager.py` |
| REST API endpoints | `bastion/api/routes.py` |
| Flask app factory | `bastion/web/app.py` |
| Plugins | `bastion/plugins/<name>/` |

## Reporting issues

Use [GitHub Issues](https://github.com/gbudja/bastion/issues) for bug reports and feature requests. Include:

- OS and Python version
- Bastion version or commit hash
- Whether you are using demo mode or live mode
- Steps to reproduce
- Relevant log output

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0-or-later license.
