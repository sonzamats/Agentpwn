# Contributing to AgentPwn

Thank you for your interest in contributing to AgentPwn! This guide will help you
get started with development, testing, and submitting changes.

## Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/wyattmatson/agentpwn.git
   cd agentpwn
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux / macOS
   .venv\Scripts\activate      # Windows
   ```

3. **Install the package in editable mode with dev dependencies:**

   ```bash
   pip install -e ".[dev]"
   ```

   This installs AgentPwn along with pytest, ruff, mypy, and other development
   tools.

## Running Tests

Run the full test suite:

```bash
pytest
```

Run tests with a coverage report:

```bash
pytest --cov=agentpwn --cov-report=term-missing
```

Skip slow or integration tests during local development:

```bash
pytest -m "not slow and not integration"
```

## Code Style

This project uses **Ruff** for linting and formatting and **mypy** for static
type checking. Please make sure your changes pass all three checks before
submitting a pull request.

```bash
# Lint
ruff check agentpwn tests

# Format check (use without --check to auto-format)
ruff format --check agentpwn tests

# Type check
mypy agentpwn
```

Key style points:

- Target Python version: 3.10+
- Line length limit: 100 characters
- All public functions and methods must have type annotations
- Use `from __future__ import annotations` where appropriate

## Adding New Attack Modules

Attack modules live in `agentpwn/attacks/`. To add a new attack:

1. Create a new file under `agentpwn/attacks/` (e.g., `my_attack.py`).
2. Subclass the base attack class defined in `agentpwn/attacks/base.py` and
   implement the required interface methods.
3. Register the attack in `agentpwn/attacks/__init__.py` so it is discoverable
   by the framework.
4. Add corresponding tests in `tests/test_attacks/`.
5. Include a YAML campaign example in `campaigns/` if the attack can be
   demonstrated standalone.

## Adding New Target Connectors

Target connectors live in `agentpwn/targets/`. To add a new connector:

1. Create a new file under `agentpwn/targets/` (e.g., `my_target.py`).
2. Subclass the base target class defined in `agentpwn/targets/base.py` and
   implement the required interface methods (connect, send, receive, etc.).
3. Register the connector in `agentpwn/targets/__init__.py`.
4. Add corresponding tests in `tests/test_targets/`.
5. If the connector requires an extra dependency, add an optional-dependencies
   group in `pyproject.toml` and guard the import accordingly.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b feature/my-change
   ```

2. Make your changes, ensuring all tests pass and code style checks are clean.

3. Write or update tests to cover your changes.

4. Commit with a clear, descriptive commit message.

5. **Push** your branch and open a pull request against `main`.

6. In the PR description, explain **what** changed and **why**. Link any related
   issues.

7. A maintainer will review your PR. Please be responsive to feedback -- we aim
   to keep the review cycle short.

### PR Checklist

- [ ] Tests pass locally (`pytest`)
- [ ] Linting passes (`ruff check`, `ruff format --check`)
- [ ] Type checking passes (`mypy agentpwn`)
- [ ] New code includes type annotations
- [ ] Documentation updated if applicable

## Questions?

Open an issue or start a discussion on GitHub. We are happy to help!
