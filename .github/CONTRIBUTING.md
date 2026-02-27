# Contributing to AgentPwn

Thank you for your interest in contributing to AgentPwn. This document provides
guidelines and information to help you get started.

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and
inclusive environment. Be constructive in feedback, patient with newcomers, and
professional in all interactions.

---

## How to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/sonzamats/Agentpwn/issues) to
   avoid duplicates.
2. Use the [bug report template](ISSUE_TEMPLATE/bug_report.md).
3. Include reproduction steps, expected behavior, actual behavior, and
   environment details.

### Suggesting Features

1. Search existing issues and discussions first.
2. Use the [feature request template](ISSUE_TEMPLATE/feature_request.md).
3. Describe the problem you are solving, not just the solution you want.

### Submitting Code

1. Fork the repository.
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature main
   ```
3. Make your changes (see [Development Setup](#development-setup) below).
4. Write or update tests.
5. Ensure all checks pass:
   ```bash
   ruff check agentpwn tests
   ruff format --check agentpwn tests
   mypy agentpwn
   pytest
   ```
6. Commit with a clear message (see [Commit Messages](#commit-messages)).
7. Push to your fork and open a pull request.

---

## Development Setup

### Prerequisites

- Python 3.10 or later
- Git

### Install

```bash
git clone https://github.com/sonzamats/Agentpwn.git
cd agentpwn
pip install -e ".[dev,all]"
```

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=agentpwn --cov-report=term-missing

# Specific test file
pytest tests/test_attacks/test_indirect_injection.py -v

# Skip slow/integration tests
pytest -m "not slow and not integration"
```

### Linting and Formatting

AgentPwn uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Lint
ruff check agentpwn tests

# Auto-fix lint issues
ruff check --fix agentpwn tests

# Format
ruff format agentpwn tests

# Check formatting without modifying
ruff format --check agentpwn tests
```

### Type Checking

```bash
mypy agentpwn
```

---

## Project Structure

```
agentpwn/
├── core/          # Engine, config, models, logging, reporting
├── targets/       # Target connectors (BaseTarget subclasses)
├── attacks/       # Attack modules (BaseAttack subclasses)
│   ├── prompt_injection/
│   ├── tool_manipulation/
│   ├── privilege_escalation/
│   ├── multi_agent/
│   └── mcp_attacks/
├── defenses/      # Reference defense implementations
└── utils/         # Shared utilities
```

---

## Writing Attack Modules

See [docs/adding_modules.md](../docs/adding_modules.md) for a complete guide.
In brief:

1. Create a file in the appropriate `agentpwn/attacks/<category>/` directory.
2. Subclass `BaseAttack`.
3. Set metadata: `name`, `category`, `description`, `severity`, `mitre_mapping`.
4. Implement `get_payloads()` and `execute()`.
5. Write tests in `tests/test_attacks/`.

The module is auto-discovered. No registration needed.

---

## Writing Target Connectors

1. Create a file in `agentpwn/targets/`.
2. Subclass `BaseTarget`.
3. Implement all abstract methods: `initialize`, `send_message`,
   `send_tool_output`, `get_tool_calls`, `reset`, `get_conversation_history`.
4. Register in `_TARGET_CONNECTORS` in `core/engine.py`.
5. Add a `TargetType` enum value in `core/models.py`.
6. Write tests in `tests/test_targets/`.

---

## Commit Messages

Use clear, descriptive commit messages:

```
<type>: <short summary>

<optional body explaining why, not what>
```

Types:

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes nor adds |
| `ci` | CI/CD changes |
| `chore` | Build, tooling, dependency updates |

Examples:

```
feat: add system prompt extraction attack module
fix: handle timeout in MCP target connector
docs: add MCP-focused campaign example
test: add coverage for parameter injection edge cases
```

---

## Pull Request Guidelines

1. **One PR per feature or fix.** Keep changes focused and reviewable.
2. **Include tests.** All new code should have corresponding test coverage.
3. **Update documentation.** If your change affects user-facing behavior, update
   the relevant docs.
4. **Pass all checks.** The CI pipeline runs lint, type check, and tests. PRs
   with failing checks will not be merged.
5. **Keep PRs small.** Large PRs are hard to review. Break big features into
   incremental PRs when possible.
6. **Describe your changes.** The PR description should explain what changed,
   why, and how to test it.

---

## Copyright and License

All contributions must be licensed under the Apache License 2.0. Include the
copyright header in all new source files:

```python
# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0
```

By submitting a pull request, you agree that your contribution is licensed
under the same terms.

---

## Security Vulnerabilities

If you discover a security vulnerability in AgentPwn itself (not in a target
system being tested), please report it responsibly:

- **Do not** open a public issue.
- Email `wyatt@matsoncapitalgroup.com` with details.
- We will acknowledge receipt within 48 hours and provide a timeline for a fix.

---

## Questions?

Open a [discussion](https://github.com/sonzamats/Agentpwn/discussions) or
reach out via the issue tracker.
