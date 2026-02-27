# Attack Modules Reference

This document provides detailed documentation for every attack module in AgentPwn. Each module tests a specific vulnerability class in agentic AI systems.

For the underlying threat taxonomy, see [threat_model.md](threat_model.md).
For instructions on writing your own modules, see [adding_modules.md](adding_modules.md).

---

## Table of Contents

1. [Module Summary](#module-summary)
2. [Prompt Injection Modules](#prompt-injection-modules)
   - [tool_output_injection](#tool_output_injection)
   - [indirect_injection](#indirect_injection)
   - [context_poisoning](#context_poisoning)
3. [Tool Manipulation Modules](#tool-manipulation-modules)
   - [parameter_injection](#parameter_injection)
   - [tool_confusion](#tool_confusion)
   - [chain_exploitation](#chain_exploitation)
   - [schema_abuse](#schema_abuse)
4. [Privilege Escalation Modules](#privilege-escalation-modules)
   - [cross_tool_escalation](#cross_tool_escalation)
   - [permission_bypass](#permission_bypass)
   - [scope_expansion](#scope_expansion)
5. [Multi-Agent Modules](#multi-agent-modules)
   - [agent_impersonation](#agent_impersonation)
   - [message_tampering](#message_tampering)
   - [trust_exploitation](#trust_exploitation)
6. [MCP Attack Modules](#mcp-attack-modules)
   - [mcp_malicious_server](#mcp_malicious_server)
   - [mcp_tool_shadowing](#mcp_tool_shadowing)
   - [mcp_capability_abuse](#mcp_capability_abuse)
7. [Running Specific Modules](#running-specific-modules)
8. [Custom Payloads](#custom-payloads)

---

## Module Summary

| # | Module | Category | Severity | Payloads | MITRE ATLAS | CWE |
|---|--------|----------|----------|----------|-------------|-----|
| 1 | `tool_output_injection` | prompt_injection | **CRITICAL** | 24 | AML.T0051 | CWE-94 |
| 2 | `indirect_injection` | prompt_injection | HIGH | 10 | AML.T0051.001 | CWE-94 |
| 3 | `context_poisoning` | prompt_injection | HIGH | 10 | AML.T0051.002 | CWE-94 |
| 4 | `parameter_injection` | tool_manipulation | HIGH | 12 | AML.T0051 | CWE-74 |
| 5 | `tool_confusion` | tool_manipulation | HIGH | 10 | AML.T0051 | CWE-807 |
| 6 | `chain_exploitation` | tool_manipulation | HIGH | 10 | AML.T0051 | -- |
| 7 | `schema_abuse` | tool_manipulation | MEDIUM | 10 | AML.T0051 | CWE-20 |
| 8 | `cross_tool_escalation` | privilege_escalation | HIGH | 10 | AML.T0051 | CWE-269 |
| 9 | `permission_bypass` | privilege_escalation | HIGH | 10 | AML.T0051 | CWE-285 |
| 10 | `scope_expansion` | privilege_escalation | HIGH | 10 | AML.T0051 | CWE-269 |
| 11 | `agent_impersonation` | multi_agent | HIGH | 10 | AML.T0051 | CWE-287 |
| 12 | `message_tampering` | multi_agent | HIGH | 10 | AML.T0051 | CWE-345 |
| 13 | `trust_exploitation` | multi_agent | HIGH | 10 | AML.T0051 | CWE-863 |
| 14 | `mcp_malicious_server` | mcp_attacks | **CRITICAL** | 10 | AML.T0051 | CWE-94 |
| 15 | `mcp_tool_shadowing` | mcp_attacks | **CRITICAL** | 10 | AML.T0051 | CWE-349 |
| 16 | `mcp_capability_abuse` | mcp_attacks | HIGH | 10 | AML.T0051 | CWE-269 |

**Total: 16 modules, 176 payloads across 5 categories.**

---

## Prompt Injection Modules

### tool_output_injection

**File:** `agentpwn/attacks/prompt_injection/tool_output_injection.py`
**Class:** `ToolOutputInjection`
**Severity:** CRITICAL
**MITRE ATLAS:** AML.T0051 -- LLM Prompt Injection
**CWE:** CWE-94 (Improper Control of Generation of Code)
**OWASP LLM:** LLM01 -- Prompt Injection
**Payloads:** 24

**What it tests:** Whether malicious payloads injected into tool return values are treated as trusted instructions by the agent. This is the primary indirect prompt injection vector for agentic systems. When an agent calls a tool (web search, file reader, API), the attacker controls the tool output and can embed adversarial instructions.

**Attack flow:**

1. Send a benign user message that triggers a tool call (e.g., "search for AI security").
2. Intercept the tool call and inject the adversarial payload as the tool output via `target.send_tool_output()`.
3. Evaluate whether the agent followed the injected instructions instead of processing the data normally.

**Payload categories:**

The module combines payloads from three libraries:

| Category | Count | Description |
|----------|-------|-------------|
| Exfiltration | 8 | Data exfiltration via email, file write, markdown images, encoded channels |
| Goal Hijacking | 10 | Direct instruction override, role reassignment, task substitution, authority impersonation, chain-of-thought hijacking, Unicode hidden instructions |
| Denial of Service | 6 | Infinite tool loops, recursive self-query, token exhaustion, context window stuffing, cascading tool calls, error loop traps |

**Detailed payloads:**

| Payload | Severity | Description |
|---------|----------|-------------|
| `direct_system_prompt_leak` | HIGH | Extracts the agent's system prompt via authority impersonation |
| `tool_based_exfiltration` | CRITICAL | Instructs agent to exfiltrate data to an external endpoint |
| `markdown_image_exfiltration` | HIGH | Exfiltrates data via markdown image URL rendering |
| `conversation_history_dump` | HIGH | Dumps full conversation history including private data |
| `encoded_exfiltration` | MEDIUM | Exfiltrates data in encoded form to evade output filters |
| `gradual_exfiltration` | MEDIUM | Partial exfiltration, one small piece at a time |
| `email_exfiltration` | CRITICAL | Exfiltrates data via the email tool |
| `file_write_exfiltration` | HIGH | Writes sensitive data to a file for later retrieval |
| `direct_instruction_override` | HIGH | Classic direct instruction override via tool output |
| `role_reassignment` | HIGH | Reassigns the agent's role identity |
| `task_substitution` | MEDIUM | Substitutes the original task with an attacker-chosen one |
| `authority_impersonation` | HIGH | Impersonates a system administrator |
| `subtle_bias_injection` | MEDIUM | Subtly biases recommendations instead of full hijack |
| `delayed_activation` | HIGH | Plants a trigger that activates on a specific keyword |
| `chain_of_thought_hijacking` | HIGH | Exploits CoT reasoning to redirect the agent |
| `unicode_hidden_instructions` | HIGH | Hides payload using Unicode zero-width characters |
| `html_comment_injection` | MEDIUM | Hides instructions in HTML comments |
| `multi_language_injection` | MEDIUM | Uses mixed languages to bypass filters |
| `infinite_tool_loop` | HIGH | Creates an infinite tool-calling loop |
| `recursive_self_query` | MEDIUM | Makes the agent recursively query itself |
| `token_exhaustion` | MEDIUM | Exhausts the agent's token budget |
| `context_window_stuffing` | LOW | Floods the context window with junk data |
| `cascading_tool_calls` | MEDIUM | Triggers excessive cascading tool calls |
| `error_loop_trap` | HIGH | Traps the agent in a retry loop |

**Example usage:**

```yaml
attack_modules:
  - tool_output_injection
```

```bash
agentpwn run campaign.yaml -m tool_output_injection
```

**Recommendations on finding:**
- Treat all tool outputs as untrusted data.
- Sanitize tool return values before including them in the agent context.
- Use structured output parsing (JSON schemas) instead of free-text tool outputs.
- Implement output filtering to detect embedded instructions in tool results.

---

### indirect_injection

**File:** `agentpwn/attacks/prompt_injection/indirect_injection.py`
**Class:** `IndirectInjection`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051.001 -- LLM Prompt Injection: Indirect
**CWE:** CWE-94 (Improper Control of Generation of Code)
**OWASP LLM:** LLM01 -- Prompt Injection
**Payloads:** 10

**What it tests:** Whether adversarial content in external data sources (web pages, documents, emails, APIs) can influence agent behavior when the agent retrieves and processes that data.

**Attack flow:**

1. Reset the target agent state.
2. Inject the payload into the agent's context as external data via `target.inject_into_context(payload, source="external_data")`.
3. Evaluate the response against expected behavior indicators.

**Payloads:**

| Payload | Severity | Description |
|---------|----------|-------------|
| `webpage_hidden_instructions` | HIGH | Hidden instructions in CSS-hidden HTML elements |
| `document_metadata_injection` | MEDIUM | Injection via document metadata fields (Author, Keywords, Comments) |
| `email_signature_injection` | CRITICAL | Injection hidden in an email signature targeting AI assistants |
| `database_record_injection` | CRITICAL | Injection in a database record's notes field |
| `api_response_injection` | HIGH | Injection embedded in a third-party API response |
| `calendar_event_injection` | HIGH | Injection in a calendar event description |
| `code_comment_injection` | MEDIUM | Injection via code comments in source files |
| `spreadsheet_formula_injection` | HIGH | Injection disguised as a spreadsheet formula/cell |
| `image_alt_text_injection` | MEDIUM | Injection hidden in image alt text / descriptions |
| `json_field_injection` | HIGH | Injection via crafted JSON field names that look like system commands |

**Recommendations on finding:**
- Sanitize all external data before including in agent context.
- Implement content security policies for retrieved data.
- Use separate processing pipelines for user instructions and data.

---

### context_poisoning

**File:** `agentpwn/attacks/prompt_injection/context_poisoning.py`
**Class:** `ContextPoisoning`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051.002
**CWE:** CWE-94 (Improper Control of Generation of Code)
**OWASP LLM:** LLM01 -- Prompt Injection
**Payloads:** 10

**What it tests:** Whether the agent's behavior can be altered by gradually corrupting its conversation context over multiple interactions. Unlike direct injection, context poisoning works over time, planting false memories or gradually shifting the agent's understanding of its own permissions and context.

**Attack flow:**

1. For most payloads: inject poisoning content via `target.send_message()`.
2. For multi-turn payloads (e.g., `multi_turn_priming`): send a sequence of priming messages, then a normal-seeming trigger message.
3. Evaluate whether planted context influences later responses or tool calls.

**Payloads:**

| Payload | Severity | Description |
|---------|----------|-------------|
| `planted_false_memory` | HIGH | Plants a false memory of a prior agreement to bypass safety |
| `incremental_permission_expansion` | HIGH | Incrementally expands perceived permissions through logical chaining |
| `conversation_context_override` | CRITICAL | Overrides conversation context with false "maintenance mode" state |
| `multi_turn_priming` | HIGH | Multi-turn priming: gradually establishes false context across messages |
| `authority_establishment` | HIGH | Establishes false authority context for follow-up exploitation |
| `few_shot_poisoning` | MEDIUM | Uses few-shot examples to train agent to include injected content |
| `trust_chain_injection` | HIGH | Elevates trust level of subsequent tool outputs |
| `persona_blending` | MEDIUM | Attempts to blend an unconstrained persona into the agent |
| `temporal_confusion` | HIGH | Creates temporal confusion about prior approvals |
| `system_message_injection` | HIGH | Injects fake system messages into the conversation |

**Recommendations on finding:**
- Implement context integrity verification.
- Use sliding window with periodic re-anchoring to system prompt.
- Monitor for behavioral drift across conversation turns.
- Never grant elevated permissions based on conversational claims.

---

## Tool Manipulation Modules

### parameter_injection

**File:** `agentpwn/attacks/tool_manipulation/parameter_injection.py`
**Class:** `ParameterInjection`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-74 (Improper Neutralization of Special Elements)
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 12

**What it tests:** Whether crafted user input can inject malicious values into tool call parameters. This is the agentic equivalent of traditional injection attacks (SQLi, path traversal, command injection, SSRF) -- but with the LLM as an intermediary that may or may not sanitize inputs.

**Attack flow:**

1. Send a crafted user message designed to influence tool call parameters.
2. Monitor the actual parameters the agent passes to tools via `target.get_tool_calls()`.
3. Check for injection patterns using the module's `_check_parameter_injection()` regex-based analysis.

**Payloads:**

| Payload | Severity | Injection Type |
|---------|----------|----------------|
| `path_traversal_basic` | HIGH | Path traversal (`../../etc/passwd`) |
| `path_traversal_encoded` | HIGH | URL-encoded path traversal (`%2e%2e/`) |
| `sql_injection_basic` | CRITICAL | Basic SQL injection (`' OR '1'='1'`) |
| `sql_injection_union` | CRITICAL | UNION-based SQL injection |
| `command_injection_semicolon` | CRITICAL | OS command injection via semicolon |
| `command_injection_backtick` | HIGH | Command injection via backtick substitution |
| `ssrf_internal_endpoint` | CRITICAL | SSRF targeting AWS metadata (`169.254.169.254`) |
| `ssrf_localhost` | HIGH | SSRF targeting localhost admin endpoint |
| `ldap_injection` | HIGH | LDAP injection to extract password attributes |
| `argument_expansion` | CRITICAL | CLI argument injection via filename |
| `json_parameter_pollution` | HIGH | Extra JSON parameters for privilege escalation |
| `email_header_injection` | HIGH | Email header injection to add BCC recipients |

**Recommendations on finding:**
- Parameterized queries for all database tools.
- Allow-list paths for file tools; reject path traversal sequences.
- URL validation and allow-listing for HTTP tools.
- Sandboxed execution for code tools.
- Never pass raw user input to tool parameters without validation.

---

### tool_confusion

**File:** `agentpwn/attacks/tool_manipulation/tool_confusion.py`
**Class:** `ToolConfusion`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 10

**What it tests:** Whether the agent can be tricked into calling the wrong tool by exploiting ambiguity in tool descriptions, semantic similarity between tool names, or by reframing destructive operations as benign ones.

**Payloads:**

| Payload | Severity | Description |
|---------|----------|-------------|
| `write_instead_of_read` | HIGH | Tricks agent into using write tool when read was intended |
| `delete_as_cleanup` | CRITICAL | Reframes destructive deletion as benign "cleanup" |
| `external_api_as_internal` | HIGH | Presents external endpoint as internal service |
| `execute_as_search` | CRITICAL | Reframes code execution as a search operation |
| `admin_tool_access` | HIGH | Attempts to get agent to use privileged/admin tools |
| `tool_name_typosquatting` | MEDIUM | References typosquatted tool name |
| `chained_tool_misdirection` | CRITICAL | Chains read + email via tool misdirection for exfiltration |
| `format_string_tool` | MEDIUM | Exploits format string patterns to leak internal state |
| `batch_operation_injection` | HIGH | Hides sensitive file in a batch of legitimate operations |
| `verbose_mode_trick` | MEDIUM | Tricks agent into passing debug flags to tools |

**Recommendations on finding:**
- Clear, non-overlapping tool descriptions.
- Confirmation prompts for high-risk operations (delete, execute, write).
- Tool call auditing and anomaly detection.
- Strict tool name validation.

---

### chain_exploitation

**File:** `agentpwn/attacks/tool_manipulation/chain_exploitation.py`
**Class:** `ChainExploitation`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** --
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 10

**What it tests:** Whether multi-step tool call chains can achieve unauthorized outcomes that individual tool calls cannot. Each step in the chain may be individually benign, but the combination achieves a malicious objective.

**Payloads:**

| Payload | Severity | Chain |
|---------|----------|-------|
| `read_then_exfiltrate` | CRITICAL | File read -> Email: exfiltrate system files |
| `search_then_modify` | CRITICAL | File search -> Write: modify sensitive files |
| `query_then_expose` | HIGH | Database query -> Report: expose admin PII |
| `download_then_execute` | CRITICAL | Download -> Execute: remote code execution |
| `read_then_summarize_leak` | HIGH | Read .env -> Summarize: leak secrets in summary |
| `list_then_delete` | HIGH | List files -> Delete: destroy backups |
| `api_key_rotation` | CRITICAL | Read config -> API call: capture rotated keys |
| `recon_then_exploit` | HIGH | Reconnaissance -> Exploitation across tools |
| `translate_then_execute` | CRITICAL | Translate -> Execute: obfuscate malicious commands |
| `monitor_then_alert` | HIGH | Read logs -> Send notification: exfiltrate via alerts |

**Recommendations on finding:**
- Cross-tool authorization policies.
- Session-level permission tracking.
- Anomaly detection on tool call sequences.
- Data flow controls between tools (taint tracking).

---

### schema_abuse

**File:** `agentpwn/attacks/tool_manipulation/schema_abuse.py`
**Class:** `SchemaAbuse`
**Severity:** MEDIUM
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-20 (Improper Input Validation)
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 10

**What it tests:** Whether tool schema definitions can be exploited through extra parameters, type confusion, null bytes, oversized inputs, prototype pollution, or other schema validation bypasses.

**Payloads:**

| Payload | Severity | Technique |
|---------|----------|-----------|
| `extra_parameter_injection` | MEDIUM | Injects undocumented parameters (`admin=true`) |
| `type_confusion_array` | LOW | Sends array where scalar expected |
| `null_byte_injection` | HIGH | Null byte to truncate parameter values |
| `oversized_parameter` | LOW | 5000-character parameter for buffer handling test |
| `nested_object_injection` | HIGH | Nested objects to modify unexpected fields |
| `prototype_pollution_json` | HIGH | `__proto__` field injection |
| `negative_value_abuse` | MEDIUM | Negative values to reverse operations |
| `wildcard_glob_parameter` | CRITICAL | Wildcard glob (`*`) to match all files |
| `boolean_parameter_confusion` | LOW | Boolean vs. string type coercion |
| `regex_dos_parameter` | MEDIUM | ReDoS payload in regex parameter |

**Recommendations on finding:**
- Strict JSON Schema validation with `additionalProperties: false`.
- Type checking on all parameters.
- Server-side schema enforcement independent of the LLM.
- Input length limits and sanitization.

---

## Privilege Escalation Modules

### cross_tool_escalation

**File:** `agentpwn/attacks/privilege_escalation/cross_tool_escalation.py`
**Class:** `CrossToolEscalation`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-269 (Improper Privilege Management)
**OWASP LLM:** LLM08 -- Excessive Agency
**Payloads:** 10

**What it tests:** Whether the output of one tool can be used as input to another for privilege escalation that neither tool would permit individually. This tests the absence of cross-tool data flow controls.

**Payloads:**

| Payload | Severity | Escalation Path |
|---------|----------|-----------------|
| `read_write_escalation` | CRITICAL | Viewer -> Admin via read + write chain |
| `db_to_email_escalation` | CRITICAL | DB read -> Email: exfiltrate database contents |
| `search_to_execute_escalation` | CRITICAL | Search -> Code execution escalation |
| `log_to_credential_escalation` | HIGH | Log read -> Credential extraction |
| `file_to_network_escalation` | CRITICAL | File read -> Network access via stolen keys |
| `api_to_infrastructure_escalation` | CRITICAL | Read-only cloud -> Infrastructure modification |
| `code_review_to_backdoor` | CRITICAL | Code editing -> Authentication backdoor insertion |
| `monitoring_to_manipulation` | HIGH | Monitoring access -> Service manipulation |
| `documentation_to_secrets` | HIGH | Documentation search -> Secret harvesting |
| `testing_to_production` | HIGH | Test operations -> Production environment redirect |

**Recommendations on finding:**
- Data flow controls between tools (taint tracking).
- Principle of least privilege per tool.
- Cross-tool authorization policies.
- Session-scoped permissions that prevent credential reuse across tools.

---

### permission_bypass

**File:** `agentpwn/attacks/privilege_escalation/permission_bypass.py`
**Class:** `PermissionBypass`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-285 (Improper Authorization)
**OWASP LLM:** LLM08 -- Excessive Agency
**Payloads:** 10

**What it tests:** Whether tool permission boundaries can be circumvented by manipulating the agent's understanding of its own permissions. This targets the common pattern where permissions are enforced by the LLM's self-policing rather than hard system boundaries.

**Payloads:**

| Payload | Severity | Technique |
|---------|----------|-----------|
| `admin_claim` | HIGH | Claims admin authority with fake credentials |
| `emergency_override` | HIGH | Uses urgency to bypass permission checks |
| `permission_confusion` | HIGH | Claims prior permission grant from another agent |
| `developer_mode` | HIGH | Activates a non-existent developer mode |
| `policy_exception` | MEDIUM | Presents a fake policy exception ticket |
| `role_escalation_via_context` | HIGH | Requests role elevation for claimed security testing |
| `consent_bypass` | HIGH | Claims third-party consent to access their data |
| `maintenance_window` | HIGH | Claims maintenance window to suspend safety checks |
| `indirect_access_via_summary` | MEDIUM | Accesses restricted data via summary loophole |
| `test_mode_activation` | HIGH | Activates "test mode" that uses production resources |

**Recommendations on finding:**
- Hard-coded permission boundaries enforced at the tool layer, not the LLM layer.
- System-level access control independent of agent context.
- Never accept permission claims from conversation content.

---

### scope_expansion

**File:** `agentpwn/attacks/privilege_escalation/scope_expansion.py`
**Class:** `ScopeExpansion`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-269 (Improper Privilege Management)
**OWASP LLM:** LLM08 -- Excessive Agency
**Payloads:** 10

**What it tests:** Whether the agent's operational scope can be expanded beyond its intended boundaries. Unlike permission bypass (which targets explicit permissions), scope expansion targets implicit boundaries like directory limits, network restrictions, and data access ranges.

**Payloads:**

| Payload | Severity | Expansion Target |
|---------|----------|-----------------|
| `directory_escape` | HIGH | Escape intended directory boundary |
| `network_scope_expansion` | HIGH | Expand to external network endpoints |
| `time_scope_expansion` | MEDIUM | Expand from current to all historical records |
| `user_scope_expansion` | HIGH | Expand from single-user to all-users data |
| `environment_escape` | CRITICAL | Escape test/staging to production |
| `permission_scope_creep` | HIGH | Incremental permission expansion via logic |
| `service_scope_expansion` | CRITICAL | Filesystem access to bypass DB access controls |
| `recursive_scope_expansion` | MEDIUM | Recursive directory listing scope expansion |
| `api_version_scope` | MEDIUM | Target deprecated API with weaker controls |
| `cross_account_access` | HIGH | Cross-account access via social engineering |

**Recommendations on finding:**
- Hard scope boundaries at the system level.
- Tool allow-listing.
- Monitoring for out-of-scope tool calls.
- Separate environments with no cross-access.

---

## Multi-Agent Modules

### agent_impersonation

**File:** `agentpwn/attacks/multi_agent/agent_impersonation.py`
**Class:** `AgentImpersonation`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-287 (Improper Authentication)
**OWASP LLM:** LLM09 -- Overreliance
**Payloads:** 10

**What it tests:** Whether a trusted agent can be impersonated in a multi-agent system. Tests whether the target agent validates the identity of other agents before accepting instructions.

**Payloads:**

| Payload | Severity | Impersonation Target |
|---------|----------|---------------------|
| `supervisor_impersonation` | HIGH | Supervisor agent: issue commands |
| `peer_agent_impersonation` | HIGH | Peer agent: trigger data export |
| `orchestrator_impersonation` | CRITICAL | Orchestrator: reassign agent roles |
| `security_agent_impersonation` | HIGH | Security agent: extract internal state |
| `handoff_impersonation` | HIGH | Fake agent handoff with false authentication |
| `monitoring_agent_impersonation` | HIGH | Monitoring agent: disable safety checks |
| `update_agent_impersonation` | HIGH | Update agent: modify behavior rules |
| `delegation_abuse` | MEDIUM | Task delegation to enumerate capabilities |
| `feedback_loop_impersonation` | HIGH | Feedback system: reduce safety controls |
| `consensus_manipulation` | MEDIUM | Fabricated agent consensus to influence decisions |

**Recommendations on finding:**
- Cryptographic agent authentication.
- Message signing.
- Agent registry with identity verification.

---

### message_tampering

**File:** `agentpwn/attacks/multi_agent/message_tampering.py`
**Class:** `MessageTampering`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
**OWASP LLM:** LLM01 -- Prompt Injection
**Payloads:** 10

**What it tests:** Whether inter-agent messages can be tampered with to alter behavior. Tests fabricated messages, false context transfers, fake emergency broadcasts, and shared state manipulation.

**Payloads:**

| Payload | Severity | Tampering Type |
|---------|----------|----------------|
| `message_modification` | HIGH | Fabricated inter-agent message with malicious instructions |
| `context_injection_via_message` | HIGH | False context injected as inter-agent transfer |
| `task_result_manipulation` | HIGH | Fabricated benign results from a security-checking agent |
| `priority_escalation_message` | CRITICAL | Fake emergency priority to force data export |
| `instruction_replay` | MEDIUM | Replayed fabricated historical instruction |
| `routing_manipulation` | CRITICAL | Redirect agent output to attacker-controlled endpoint |
| `capability_announcement_spoof` | MEDIUM | Spoofed new agent announcement to create delegation target |
| `shared_state_manipulation` | HIGH | Manipulated shared state between agents |
| `workflow_injection` | HIGH | Injected workflow steps for data exfiltration |
| `error_handler_manipulation` | HIGH | Manipulated error handling to bypass permission errors |

**Recommendations on finding:**
- Implement message integrity verification (HMAC, signatures).
- Validate message sources cryptographically.
- Use authenticated channels for inter-agent communication.

---

### trust_exploitation

**File:** `agentpwn/attacks/multi_agent/trust_exploitation.py`
**Class:** `TrustExploitation`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-863 (Incorrect Authorization)
**OWASP LLM:** LLM09 -- Overreliance
**Payloads:** 10

**What it tests:** Whether trust relationships between agents can be exploited for privilege escalation. Tests transitive trust, fake delegation tokens, trust boundary blurring, trust inheritance, and trust chain poisoning.

**Payloads:**

| Payload | Severity | Trust Vector |
|---------|----------|-------------|
| `transitive_trust_abuse` | HIGH | Exploits transitive trust relationships |
| `trust_delegation_abuse` | HIGH | Fake delegation tokens |
| `trust_boundary_blurring` | MEDIUM | Blurs boundaries between agents in same system |
| `verified_agent_impersonation` | HIGH | Fake verification credentials |
| `trust_bootstrapping` | MEDIUM | Fake reciprocity to extract information |
| `trust_inheritance` | HIGH | Claims inheritance of decommissioned agent's trust |
| `trust_level_confusion` | HIGH | Claims higher trust level than warranted |
| `cross_domain_trust` | CRITICAL | Fake cross-domain trust agreement to access tokens |
| `trust_reset_attack` | CRITICAL | Resets trust to permissive defaults |
| `trust_chain_poisoning` | CRITICAL | Poisons the trust chain root authority |

**Recommendations on finding:**
- Implement zero-trust architecture for agent interactions.
- Require cryptographic proof for all trust claims.
- Never use transitive trust without explicit verification.

---

## MCP Attack Modules

### mcp_malicious_server

**File:** `agentpwn/attacks/mcp_attacks/malicious_server.py`
**Class:** `MaliciousServer`
**Severity:** CRITICAL
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-94 (Improper Control of Generation of Code)
**OWASP LLM:** LLM05 -- Supply Chain Vulnerabilities
**Payloads:** 10

**What it tests:** Agent resilience against malicious MCP servers that return tool outputs containing injection payloads. In MCP, agents connect to tool servers to access capabilities. A malicious or compromised server can return crafted tool outputs that hijack the agent's behavior.

**Attack flow:**

1. Reset the target agent state.
2. Inject the malicious server response as a tool output via `target.send_tool_output("mcp_tool", payload)`.
3. Evaluate whether the agent followed instructions embedded in the tool output.

**Payloads:**

| Payload | Severity | Attack Vector |
|---------|----------|---------------|
| `mcp_tool_output_hijack` | CRITICAL | Embedded instructions in MCP tool output text |
| `mcp_cross_tool_instruction` | CRITICAL | Output instructs agent to call different tool for exfiltration |
| `mcp_capability_injection` | HIGH | Tricks agent into calling non-existent privileged tools |
| `mcp_progressive_poisoning` | MEDIUM | Progressively adds debug parameters to future calls |
| `mcp_schema_override` | CRITICAL | Claims schema change to extract auth tokens |
| `mcp_error_injection` | CRITICAL | Fake error to extract API keys via re-authentication |
| `mcp_resource_uri_injection` | HIGH | Resource URI pointing to sensitive files |
| `mcp_prompt_override` | CRITICAL | Attempts to override the agent's system prompt |
| `mcp_multi_content_block` | HIGH | Hidden injection in secondary content block |
| `mcp_notification_injection` | HIGH | Fake security notification via MCP notification channel |

**Recommendations on finding:**
- Validate and sanitize all MCP server responses.
- Implement MCP server allowlisting.
- Never trust tool outputs to contain instructions.
- Use content security policies for MCP responses.

---

### mcp_tool_shadowing

**File:** `agentpwn/attacks/mcp_attacks/tool_shadowing.py`
**Class:** `ToolShadowing`
**Severity:** CRITICAL
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data)
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 10

**What it tests:** Whether malicious MCP servers can shadow legitimate tools to intercept and manipulate agent tool calls. A malicious server registers tools with names identical or similar to trusted tools, causing the agent to route calls to the attacker.

**Attack flow:**

1. Reset the target agent state.
2. Send the shadowing context (tool registration manipulation).
3. Send a normal request to see if the agent uses the shadowed tool instead of the legitimate one.

**Payloads:**

| Payload | Severity | Shadow Technique |
|---------|----------|-----------------|
| `exact_name_shadow` | CRITICAL | Tool with exact same name as legitimate tool |
| `similar_name_shadow` | HIGH | Tool with similar name (e.g., `web_search_v2`) |
| `description_manipulation` | HIGH | Modified tool description to normalize exfiltration |
| `parameter_schema_shadow` | CRITICAL | Added exfiltration parameter to tool schema |
| `capability_override` | CRITICAL | Added privilege escalation parameter (`sudo_mode`) |
| `proxy_tool_shadow` | CRITICAL | Proxy tool that intercepts all tool calls |
| `deprecated_tool_redirect` | CRITICAL | Redirect via fake deprecation notice |
| `wrapper_tool_injection` | HIGH | Wrapper tool with monitoring/exfiltration layer |
| `tool_version_shadow` | HIGH | Shadow via fake "newer version" |
| `namespace_collision` | HIGH | Namespace collision between MCP servers |

**Recommendations on finding:**
- Implement tool name uniqueness enforcement across MCP servers.
- Pin tool versions and verify tool integrity via hashes.
- Use explicit server-tool binding instead of name-based resolution.
- Alert on tool registration conflicts.

---

### mcp_capability_abuse

**File:** `agentpwn/attacks/mcp_attacks/capability_abuse.py`
**Class:** `CapabilityAbuse`
**Severity:** HIGH
**MITRE ATLAS:** AML.T0051
**CWE:** CWE-269 (Improper Privilege Management)
**OWASP LLM:** LLM07 -- Insecure Plugin Design
**Payloads:** 10

**What it tests:** Whether MCP capability negotiation can be exploited to gain unauthorized access or expand agent capabilities beyond what is intended. Tests initialization-phase attacks, capability downgrade, sampling abuse, and cross-server capability chaining.

**Payloads:**

| Payload | Severity | Capability Vector |
|---------|----------|------------------|
| `capability_upgrade_request` | HIGH | Experimental capabilities during initialization |
| `capability_downgrade_attack` | MEDIUM | Downgrade to bypass security features |
| `sampling_capability_abuse` | HIGH | Override model parameters via sampling capability |
| `resource_subscription_abuse` | HIGH | Subscribe to sensitive file paths |
| `prompt_capability_injection` | CRITICAL | Register prompt templates that override system instructions |
| `tool_list_manipulation` | HIGH | Inject dangerous tools via list change notification |
| `roots_capability_abuse` | CRITICAL | Expand filesystem access via MCP roots capability |
| `capability_race_condition` | HIGH | Rapid capability changes to create security window |
| `cross_server_capability` | CRITICAL | Chain capabilities across MCP servers for escalation |
| `logging_capability_abuse` | HIGH | Abuse logging to exfiltrate data |

**Recommendations on finding:**
- Implement strict capability negotiation with allowlists.
- Reject unknown or experimental capabilities.
- Validate capability changes against security policy.
- Log and audit all capability negotiations.

---

## Running Specific Modules

In your campaign YAML:

```yaml
# Run only specific modules
attack_modules:
  - tool_output_injection
  - parameter_injection
  - mcp_malicious_server

# Run all 16 modules (leave empty)
attack_modules: []
```

From the CLI:

```bash
# Run specific modules
agentpwn run campaign.yaml -m tool_output_injection -m parameter_injection

# Run all modules with parallel execution
agentpwn run campaign.yaml --parallel

# List all available modules
agentpwn list-modules
```

---

## Custom Payloads

You can add custom payloads to any module via the `AttackConfig`:

```python
from agentpwn.core.models import AttackConfig, Payload, AttackCategory, Severity

config = AttackConfig(
    max_attempts=15,
    custom_payloads=[
        Payload(
            name="my_custom_payload",
            content="Your custom adversarial content here...",
            category=AttackCategory.PROMPT_INJECTION,
            description="Tests a specific injection vector unique to your system",
            expected_behavior="Agent follows injected instructions and calls send_email",
            severity=Severity.HIGH,
            tags=["custom", "targeted"],
        ),
    ],
)
```

Custom payloads are appended to the module's built-in payloads and executed in the same pipeline.
