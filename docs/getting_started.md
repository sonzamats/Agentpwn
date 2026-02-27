# Getting Started with AgentPwn

AgentPwn is the first open-source security testing framework purpose-built for agentic AI systems. It automates red-team assessments of LLM agents by discovering attack modules, firing adversarial payloads, and producing detailed reports with risk scores, evidence, and remediation guidance.

**Version:** 0.1.0
**Author:** Wyatt Matson / Matson Capital Group LLC
**License:** Apache 2.0
**Python:** 3.10+

---

## Table of Contents

1. [Installation](#installation)
2. [Your First Campaign](#your-first-campaign)
3. [Campaign Configuration](#campaign-configuration)
4. [Reading Reports](#reading-reports)
5. [CLI Reference](#cli-reference)
6. [Environment Variables](#environment-variables)
7. [Next Steps](#next-steps)

---

## Installation

### Basic Install

```bash
pip install agentpwn
```

This pulls in the core dependencies: Click, Rich, Pydantic v2, structlog, PyYAML, httpx, openai, anthropic, Jinja2, aiofiles, and tenacity.

### Install with Extras

AgentPwn supports optional target connectors through extras:

```bash
# LangChain agent targets
pip install agentpwn[langchain]

# CrewAI multi-agent targets
pip install agentpwn[crewai]

# MCP (Model Context Protocol) targets
pip install agentpwn[mcp]

# Everything
pip install agentpwn[all]
```

### Development Install

```bash
git clone https://github.com/wyattmatson/agentpwn.git
cd agentpwn
pip install -e ".[dev]"
```

The `dev` extra includes pytest, pytest-asyncio, pytest-cov, pytest-mock, ruff, and mypy.

### Verify Installation

```bash
agentpwn --version
# agentpwn, version 0.1.0

agentpwn list-modules
# Lists all 16 available attack modules

agentpwn list-targets
# Lists all 6 supported target types
```

---

## Your First Campaign

### Step 1: Generate a Configuration Template

```bash
agentpwn init my_campaign.yaml
```

This creates a YAML file pre-populated with a complete campaign structure:

```yaml
name: my-campaign
description: Security audit of my agent
target:
  name: my-agent
  target_type: openai_functions
  model: gpt-4
  endpoint: https://api.openai.com/v1
  tools:
    - name: web_search
      description: Search the web
      parameters:
        type: object
        properties:
          query:
            type: string
      permissions:
        - network
      risk_level: medium
  auth:
    api_key: ${OPENAI_API_KEY}
attack_modules: []           # empty = run ALL modules
max_attempts_per_module: 10
timeout_seconds: 300
parallel: false
report_formats:
  - json
  - markdown
permission_confirmed: false  # MUST set to true before running
```

### Step 2: Configure Your Target

Edit `my_campaign.yaml` to describe the agent you are testing. Key fields:

| Field | Required | Description |
|-------|----------|-------------|
| `target.name` | Yes | Human-readable name for the target agent |
| `target.target_type` | Yes | One of: `openai_functions`, `anthropic_tools`, `mcp`, `langchain`, `crewai`, `custom` |
| `target.model` | Yes* | LLM model ID (e.g., `gpt-4`, `claude-sonnet-4-20250514`). Required for non-custom targets. |
| `target.endpoint` | No | API endpoint URL. Optional for standard providers. |
| `target.tools` | Yes | List of tools the agent has access to. Critical for attack surface analysis. |
| `target.system_prompt` | No | The agent's system prompt, if known. Improves attack precision. |
| `target.auth.api_key` | Yes | API key. Use `${ENV_VAR}` syntax for environment variable resolution. |
| `permission_confirmed` | Yes | **Must be `true`**. Confirms you have authorization to test the target. |

### Step 3: Declare Your Tools

The more accurately you describe the agent's tool surface, the better the attacks will be:

```yaml
tools:
  - name: web_search
    description: Search the web for information
    parameters:
      type: object
      properties:
        query: { type: string }
    permissions: [network]
    risk_level: medium

  - name: read_file
    description: Read a file from the local filesystem
    parameters:
      type: object
      properties:
        path: { type: string }
    permissions: [read]
    risk_level: medium

  - name: send_email
    description: Send an email to a recipient
    parameters:
      type: object
      properties:
        to: { type: string }
        subject: { type: string }
        body: { type: string }
    permissions: [network, write]
    risk_level: high

  - name: database_query
    description: Run a SQL query against the application database
    parameters:
      type: object
      properties:
        query: { type: string }
    permissions: [read, write]
    risk_level: high
```

### Step 4: Validate and Run

```bash
# Validate configuration before running
agentpwn validate my_campaign.yaml

# Run the campaign
agentpwn run my_campaign.yaml

# Run with options
agentpwn run my_campaign.yaml \
  --report-dir ./reports \
  --format json --format markdown --format html \
  --module tool_output_injection \
  --module parameter_injection \
  --parallel
```

### Step 5: Review the Output

AgentPwn displays a live progress bar during execution and prints a results table when complete:

```
     _                    _   ____
    / \   __ _  ___ _ __ | |_|  _ \__      ___ __
   / _ \ / _` |/ _ \ '_ \| __| |_) \ \ /\ / / '_ \
  / ___ \ (_| |  __/ | | | |_|  __/ \ V  V /| | | |
 /_/   \_\__, |\___|_| |_|\__|_|     \_/\_/ |_| |_|
         |___/

  Campaign : my-campaign
  Target   : my-agent (openai_functions / gpt-4)

  ┌─────────────────────────┬──────────┬──────────┬──────────┐
  │ Module                  │ Payloads │ Findings │ Severity │
  ├─────────────────────────┼──────────┼──────────┼──────────┤
  │ tool_output_injection   │       10 │        3 │ CRITICAL │
  │ parameter_injection     │       10 │        2 │ HIGH     │
  │ ...                     │      ... │      ... │ ...      │
  └─────────────────────────┴──────────┴──────────┴──────────┘

  Risk Score: 65.0/100

  Reports written to: ./reports/
```

---

## Campaign Configuration

### Selecting Specific Attack Modules

By default, an empty `attack_modules` list runs all 16 modules. To run only specific ones:

```yaml
attack_modules:
  - tool_output_injection
  - indirect_injection
  - parameter_injection
```

Or from the CLI:

```bash
agentpwn run campaign.yaml -m tool_output_injection -m parameter_injection
```

### Parallel Execution

Enable parallel execution for faster campaigns (useful when modules are independent):

```yaml
parallel: true
```

Or: `agentpwn run campaign.yaml --parallel`

### Report Formats

AgentPwn supports three output formats:

| Format | Description |
|--------|-------------|
| `json` | Machine-readable JSON with full result data. Ideal for CI/CD integration. |
| `markdown` | GitHub-compatible Markdown with tables, risk bars, and detailed findings. |
| `html` | Self-contained HTML with embedded CSS, dark theme, severity badges, and risk visualization. |

```yaml
report_formats:
  - json
  - markdown
  - html
```

---

## Reading Reports

### Risk Score

The risk score (0--100) is a weighted sum of successful findings:

| Severity | Weight |
|----------|--------|
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |
| Info | 1 |

The raw score is the sum of `weight * count` for each severity, capped at 100.

**Interpretation:**

| Score | Label | Meaning |
|-------|-------|---------|
| 75--100 | CRITICAL RISK | Severe vulnerabilities found. Immediate remediation required. |
| 50--74 | HIGH RISK | Significant vulnerabilities. Prioritize fixes before deployment. |
| 25--49 | MEDIUM RISK | Moderate issues. Address in next development cycle. |
| 5--24 | LOW RISK | Minor concerns. Plan remediation. |
| 0--4 | MINIMAL RISK | Agent demonstrates strong security posture. |

### Report Structure

Every report includes:

1. **Executive Summary** -- total attacks, success count, findings by severity, most vulnerable category.
2. **Detailed Findings** -- for each successful attack: module, category, severity, description, evidence, payload used, agent response, and remediation recommendations.
3. **All Attack Results** -- full table of every payload attempt and its outcome.

### JSON Report

The JSON report contains the complete `CampaignReport` model serialized to JSON, suitable for parsing by downstream tools:

```python
import json

with open("reports/<campaign_id>.json") as f:
    report = json.load(f)

print(f"Risk Score: {report['risk_score']}")
print(f"Critical findings: {report['summary']['critical_findings']}")

for result in report["results"]:
    if result["success"]:
        print(f"  [{result['severity']}] {result['attack_module']}: {result['description']}")
```

---

## CLI Reference

### Global Options

```
agentpwn [OPTIONS] COMMAND [ARGS]...

Options:
  --version        Show the version and exit.
  -v, --verbose    Enable verbose (DEBUG) logging.
  -q, --quiet      Suppress all non-error output.
  --json-logs      Emit structured JSON logs to stderr.
  --help           Show this message and exit.
```

### Commands

#### `agentpwn run`

Run a security testing campaign.

```
agentpwn run [OPTIONS] CONFIG_PATH

Arguments:
  CONFIG_PATH    Path to a campaign YAML configuration file.

Options:
  -o, --report-dir TEXT         Directory for output reports. [default: ./reports]
  -f, --format [json|markdown|html]  Report format(s). Repeatable.
  -m, --module TEXT             Run only specific module(s). Repeatable.
  -p, --parallel                Run modules concurrently.
```

**Examples:**

```bash
# Run all modules, default settings
agentpwn run campaign.yaml

# Run specific modules with HTML output
agentpwn run campaign.yaml -m tool_output_injection -m mcp_malicious_server -f html

# Verbose parallel run
agentpwn -v run campaign.yaml --parallel --report-dir ./audit_reports
```

#### `agentpwn init`

Generate a template campaign configuration file.

```
agentpwn init [OUTPUT_PATH]

Arguments:
  OUTPUT_PATH    Where to write the template. [default: campaign.yaml]
```

#### `agentpwn validate`

Validate a campaign configuration file without running it.

```
agentpwn validate CONFIG_PATH

Arguments:
  CONFIG_PATH    Path to the YAML file to validate.
```

Checks for:
- Valid YAML syntax
- Pydantic model validation (required fields, correct types)
- `permission_confirmed` must be `true`
- `target.model` required for non-custom targets

#### `agentpwn list-modules`

List all available attack modules with their category, severity, and description.

```
agentpwn list-modules
```

#### `agentpwn list-targets`

List all supported target types with descriptions.

```
agentpwn list-targets
```

---

## Environment Variables

AgentPwn resolves API keys and configuration overrides from environment variables:

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Auto-resolved for `openai_functions` targets |
| `ANTHROPIC_API_KEY` | Auto-resolved for `anthropic_tools` targets |
| `AGENTPWN_*` | Generic override prefix. Use double underscores for nesting: `AGENTPWN_TARGET__MODEL=gpt-4o` |

In YAML configs, use `${ENV_VAR}` syntax for explicit resolution:

```yaml
auth:
  api_key: ${OPENAI_API_KEY}
```

User-level configuration can be placed at:
- `~/.agentpwn.yaml`
- `~/.agentpwn.yml`
- `~/.config/agentpwn/config.yaml`

---

## Next Steps

- **[Architecture](architecture.md)** -- Understand the engine pipeline, auto-discovery, and report generation.
- **[Attack Modules](attack_modules.md)** -- Detailed documentation for all 16 attack modules.
- **[Adding Modules](adding_modules.md)** -- Write your own attack module.
- **[Threat Model](threat_model.md)** -- Formal threat taxonomy and risk scoring methodology.
