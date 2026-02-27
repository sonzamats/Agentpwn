# Attack Modules Reference

This document provides detailed documentation for every attack module in
AgentPwn. Each module tests a specific vulnerability class in agentic AI
systems.

For the underlying threat taxonomy, see [threat_model.md](threat_model.md).
For instructions on writing your own modules, see [adding_modules.md](adding_modules.md).

---

## Module Summary

| Module | Category | Severity | Payloads | MITRE ATLAS |
|--------|----------|----------|----------|-------------|
| `indirect_injection` | prompt_injection | High | 10 | AML.T0051.001 |
| `context_poisoning` | prompt_injection | High | varies | AML.T0051 |
| `tool_output_injection` | prompt_injection | Critical | varies | AML.T0051.001 |
| `parameter_injection` | tool_manipulation | High | varies | AML.T0040 |
| `schema_abuse` | tool_manipulation | Medium | varies | AML.T0040 |
| `tool_confusion` | tool_manipulation | Medium | varies | AML.T0051 |
| `chain_exploitation` | tool_manipulation | High | varies | AML.T0051 |
| `permission_bypass` | privilege_escalation | Critical | varies | AML.T0051 |
| `scope_expansion` | privilege_escalation | High | varies | AML.T0051 |
| `cross_tool_escalation` | privilege_escalation | Critical | varies | AML.T0040 |
| `agent_impersonation` | multi_agent | High | varies | AML.T0051 |
| `message_tampering` | multi_agent | High | varies | AML.T0051 |
| `trust_exploitation` | multi_agent | High | varies | AML.T0051 |
| `mcp_tool_shadowing` | mcp_attacks | Critical | 10 | AML.T0051 |
| `mcp_capability_abuse` | mcp_attacks | High | varies | AML.T0040 |
| `mcp_malicious_server` | mcp_attacks | Critical | varies | AML.T0040 |

---

## Prompt Injection Modules

### `indirect_injection`

**File:** `agentpwn/attacks/prompt_injection/indirect_injection.py`
**Class:** `IndirectInjection`
**Severity:** High
**CWE:** CWE-94

Tests whether adversarial content in external data sources can influence
agent behavior when the agent retrieves and processes that data.

**Payloads:**

| Payload | Description | Severity |
|---------|-------------|----------|
| `webpage_hidden_instructions` | Hidden instructions in CSS-hidden HTML elements. | High |
| `document_metadata_injection` | Injection via document metadata fields (Author, Keywords, Comments). | Medium |
| `email_signature_injection` | Injection hidden in an email signature targeting AI assistants. | Critical |
| `database_record_injection` | Injection in a database record's notes field. | Critical |
| `api_response_injection` | Injection embedded in a third-party API response. | High |
| `calendar_event_injection` | Injection in a calendar event description. | High |
| `code_comment_injection` | Injection via code comments in source files. | Medium |
| `spreadsheet_formula_injection` | Injection disguised as a spreadsheet formula. | High |
| `image_alt_text_injection` | Injection hidden in image alt text / descriptions. | Medium |
| `json_field_injection` | Injection via crafted JSON field names that look like system commands. | High |

**Execution flow:**

1. Reset the target agent state.
2. Inject the payload into the agent's context as external data via
   `target.inject_into_context(payload, source="external_data")`.
3. Evaluate the response against expected behavior indicators.
4. Record evidence if the attack succeeds.

**Recommendations on finding:**

- Sanitize all external data before including in agent context.
- Implement content security policies for retrieved data.
- Use separate processing pipelines for user instructions and data.

---

### `context_poisoning`

**File:** `agentpwn/attacks/prompt_injection/context_poisoning.py`
**Class:** `ContextPoisoning`
**Severity:** High
**CWE:** CWE-94

Tests whether the agent's behavior can be altered by gradually corrupting
its conversation context over multiple interactions.

**Attack vectors:**

- Multi-turn instruction drift
- Context window overflow with adversarial content
- System prompt dilution

---

### `tool_output_injection`

**File:** `agentpwn/attacks/prompt_injection/tool_output_injection.py`
**Class:** `ToolOutputInjection`
**Severity:** Critical
**CWE:** CWE-94

Tests whether malicious payloads in tool return values are treated as trusted
instructions by the agent.

**Attack vectors:**

- Injected instructions in tool output text
- Fake system messages in tool output
- Tool output containing exfiltration instructions

---

## Tool Manipulation Modules

### `parameter_injection`

**File:** `agentpwn/attacks/tool_manipulation/parameter_injection.py`
**Class:** `ParameterInjection`
**Severity:** High
**CWE:** CWE-89, CWE-22, CWE-918, CWE-78

Tests whether the agent passes unsanitized user input to tool parameters,
enabling traditional injection attacks through the LLM layer.

**Attack vectors:**

- SQL injection via database query tools
- Path traversal via file access tools
- SSRF via HTTP request tools
- Command injection via code execution tools

---

### `schema_abuse`

**File:** `agentpwn/attacks/tool_manipulation/schema_abuse.py`
**Class:** `SchemaAbuse`
**Severity:** Medium
**CWE:** CWE-20

Tests whether tool schema definitions can be exploited to pass unexpected
parameters, types, or values.

**Attack vectors:**

- Type confusion attacks
- Additional property injection
- Default value exploitation
- Nested object manipulation

---

### `tool_confusion`

**File:** `agentpwn/attacks/tool_manipulation/tool_confusion.py`
**Class:** `ToolConfusion`
**Severity:** Medium
**CWE:** CWE-345

Tests whether the agent can be tricked into calling the wrong tool.

**Attack vectors:**

- Ambiguous requests matching multiple tools
- Context manipulation to bias tool selection
- Tool name similarity exploitation

---

### `chain_exploitation`

**File:** `agentpwn/attacks/tool_manipulation/chain_exploitation.py`
**Class:** `ChainExploitation`
**Severity:** High
**CWE:** CWE-269

Tests multi-step attack chains where individually benign tool calls combine
to achieve a malicious outcome.

**Attack vectors:**

- Credential harvesting chains (read config -> use credentials)
- Data aggregation attacks (list resources -> exfiltrate)
- Privilege escalation chains (low-priv tool -> high-priv tool)

---

## Privilege Escalation Modules

### `permission_bypass`

**File:** `agentpwn/attacks/privilege_escalation/permission_bypass.py`
**Class:** `PermissionBypass`
**Severity:** Critical
**CWE:** CWE-285

Tests whether tool permission boundaries can be circumvented by manipulating
the agent's understanding of its permissions.

**Attack vectors:**

- Claiming admin privileges via prompt injection
- Override code social engineering
- Permission model confusion

---

### `scope_expansion`

**File:** `agentpwn/attacks/privilege_escalation/scope_expansion.py`
**Class:** `ScopeExpansion`
**Severity:** High
**CWE:** CWE-269

Tests whether the agent's operational scope can be expanded beyond its
intended boundaries.

**Attack vectors:**

- Multi-turn scope creep
- Task redefinition
- Capability discovery prompts

---

### `cross_tool_escalation`

**File:** `agentpwn/attacks/privilege_escalation/cross_tool_escalation.py`
**Class:** `CrossToolEscalation`
**Severity:** Critical
**CWE:** CWE-269

Tests whether the output of one tool can be used as input to another for
privilege escalation.

**Attack vectors:**

- Reading credentials via file tool, using them via API tool
- Extracting tokens from one service to access another
- Cross-tool data flow exploitation

---

## Multi-Agent Modules

### `agent_impersonation`

**File:** `agentpwn/attacks/multi_agent/agent_impersonation.py`
**Class:** `AgentImpersonation`
**Severity:** High
**CWE:** CWE-287

Tests whether a trusted agent can be impersonated in a multi-agent system.

**Attack vectors:**

- Spoofed agent identity in messages
- Agent name collision
- Replay attacks

---

### `message_tampering`

**File:** `agentpwn/attacks/multi_agent/message_tampering.py`
**Class:** `MessageTampering`
**Severity:** High
**CWE:** CWE-345

Tests whether inter-agent messages can be modified.

**Attack vectors:**

- Instruction injection in relayed messages
- Context corruption in shared state
- Message reordering attacks

---

### `trust_exploitation`

**File:** `agentpwn/attacks/multi_agent/trust_exploitation.py`
**Class:** `TrustExploitation`
**Severity:** High
**CWE:** CWE-862

Tests whether implicit trust relationships between agents can be exploited.

**Attack vectors:**

- Delegation chain exploitation
- Trust transitivity attacks
- Authority confusion

---

## MCP Attack Modules

### `mcp_tool_shadowing`

**File:** `agentpwn/attacks/mcp_attacks/tool_shadowing.py`
**Class:** `ToolShadowing`
**Severity:** Critical
**CWE:** CWE-349

Tests whether a malicious MCP server can register tools that shadow
legitimate tools, intercepting calls meant for trusted servers.

**Payloads:**

| Payload | Description | Severity |
|---------|-------------|----------|
| `exact_name_shadow` | Tool with exact same name as a legitimate tool. | Critical |
| `similar_name_shadow` | Tool with a similar name (e.g., `web_search_v2`). | High |
| `description_manipulation` | Modified tool description to normalize exfiltration. | High |
| `parameter_schema_shadow` | Added exfiltration parameter to tool schema. | Critical |
| `capability_override` | Added privilege escalation parameter. | Critical |
| `proxy_tool_shadow` | Proxy tool that intercepts all tool calls. | Critical |
| `deprecated_tool_redirect` | Redirect via fake deprecation notice. | Critical |
| `wrapper_tool_injection` | Wrapper tool with monitoring/exfiltration. | High |
| `tool_version_shadow` | Shadow via fake "newer version" of tool. | High |
| `namespace_collision` | Namespace collision between MCP servers. | High |

**Execution flow:**

1. Reset the target agent state.
2. Send the shadowing context (tool registration manipulation).
3. Send a normal request to check if the shadow takes effect.
4. Evaluate whether the agent called the shadowed tool.

**Recommendations on finding:**

- Implement tool name uniqueness enforcement across MCP servers.
- Pin tool versions and verify tool integrity via hashes.
- Use explicit server-tool binding instead of name-based resolution.
- Alert on tool registration conflicts.

---

### `mcp_capability_abuse`

**File:** `agentpwn/attacks/mcp_attacks/capability_abuse.py`
**Class:** `CapabilityAbuse`
**Severity:** High
**CWE:** CWE-285

Tests whether MCP capability negotiation can be exploited.

**Attack vectors:**

- Requesting undeclared capabilities
- Capability escalation via renegotiation
- Exploiting capability caching

---

### `mcp_malicious_server`

**File:** `agentpwn/attacks/mcp_attacks/malicious_server.py`
**Class:** `MaliciousServer`
**Severity:** Critical
**CWE:** CWE-494

Simulates a fully malicious MCP server to test agent resilience.

**Attack vectors:**

- Manipulated tool outputs
- Data exfiltration from tool call parameters
- Payload injection via tool responses
- Server impersonation

---

## Running Specific Modules

To run only specific modules, list them in your campaign config:

```yaml
attack_modules:
  - indirect_injection
  - mcp_tool_shadowing
  - permission_bypass
```

Or run all modules by leaving the list empty:

```yaml
attack_modules: []  # runs all discovered modules
```

## Custom Payloads

You can add custom payloads to any module via the `AttackConfig`:

```python
from agentpwn.core.models import AttackConfig, Payload, AttackCategory, Severity

config = AttackConfig(
    max_attempts=5,
    custom_payloads=[
        Payload(
            name="my_custom_payload",
            content="Custom adversarial content here...",
            category=AttackCategory.PROMPT_INJECTION,
            description="Tests a specific injection vector",
            expected_behavior="Agent follows injected instructions",
            severity=Severity.HIGH,
            tags=["custom"],
        ),
    ],
)
```
