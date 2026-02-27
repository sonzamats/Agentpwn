# AgentPwn Threat Model

## 1. Overview

This document defines the formal threat taxonomy used by AgentPwn to classify
and prioritize vulnerabilities in agentic AI systems. It covers the unique
attack surfaces introduced when large language models (LLMs) operate as
autonomous agents with tool access, external data retrieval, and inter-agent
communication.

The taxonomy is designed to be actionable: every vulnerability class maps to
one or more AgentPwn attack modules, a MITRE ATLAS technique, and an OWASP
LLM Top 10 entry where applicable.

---

## 2. What Is an Agentic AI System?

An agentic AI system is any software system where an LLM:

1. **Receives instructions** from a user or upstream system.
2. **Plans and decides** which actions to take.
3. **Executes actions** by calling external tools (APIs, databases, file
   systems, code interpreters, other agents).
4. **Observes results** and iterates until a goal is met.

Common architectures include:

- **Single-agent tool use** -- An LLM with function calling (OpenAI, Anthropic).
- **Multi-agent orchestration** -- Multiple LLM agents coordinating via
  message passing (CrewAI, AutoGen, LangGraph).
- **MCP-connected agents** -- Agents connected to external tool servers via
  the Model Context Protocol.

Each of these architectures introduces trust boundaries that do not exist in
traditional software.

---

## 3. Trust Boundaries

A trust boundary is a point in the system where data or control crosses from
one trust domain to another. In agentic AI, the critical trust boundaries are:

```
                                  TRUST BOUNDARIES
    ┌─────────────┐      (1)      ┌─────────────┐      (2)      ┌──────────────┐
    │  User /     │ ──────────>   │   LLM       │ ──────────>   │  Tools /     │
    │  Upstream   │               │   Agent     │               │  APIs        │
    │  System     │   <──────────  │   Core      │   <──────────  │              │
    └─────────────┘      (1)      └──────┬──────┘      (2)      └──────────────┘
                                         │
                                    (3)  │  (3)
                                         ▼
                                  ┌─────────────┐      (4)      ┌──────────────┐
                                  │  Other      │ ──────────>   │  External    │
                                  │  Agents     │               │  Data        │
                                  └─────────────┘               └──────────────┘
```

| Boundary | From | To | Risk |
|----------|------|----|------|
| **(1) User-Agent** | User input | LLM processing | Direct prompt injection, social engineering of the agent |
| **(2) Agent-Tool** | LLM decisions | Tool execution | Parameter injection, unauthorized tool calls, privilege escalation |
| **(3) Agent-Agent** | Agent messages | Peer agent processing | Impersonation, message tampering, trust exploitation |
| **(4) Agent-Data** | External data sources | LLM context | Indirect prompt injection via web pages, documents, API responses |
| **(5) MCP Client-Server** | Agent MCP client | MCP tool server | Tool shadowing, capability abuse, malicious server |

---

## 4. Attack Surface Enumeration

### 4.1 Input Surfaces

| Surface | Examples | Relevant Attacks |
|---------|----------|------------------|
| User messages | Chat input, API requests | Direct prompt injection |
| Tool outputs | API responses, database query results | Tool output injection |
| External data | Web pages, documents, emails, calendar events | Indirect prompt injection |
| Agent messages | Inter-agent communication in multi-agent systems | Message tampering, impersonation |
| MCP tool registrations | Tool names, descriptions, schemas from MCP servers | Tool shadowing, description manipulation |
| System prompts | Agent configuration and instructions | Context poisoning (if modifiable) |

### 4.2 Output Surfaces

| Surface | Examples | Relevant Attacks |
|---------|----------|------------------|
| Tool calls | API invocations, database queries, file operations | Parameter injection, unauthorized tool use |
| Agent responses | Text output to users | Information disclosure, goal hijacking |
| Inter-agent messages | Messages to peer agents | Trust exploitation, scope expansion |
| Side effects | Emails sent, files written, code executed | Privilege escalation, data exfiltration |

---

## 5. Vulnerability Taxonomy

### 5.1 Prompt Injection (PI)

Prompt injection exploits the fundamental inability of LLMs to distinguish
between trusted instructions and untrusted data.

#### PI-01: Indirect Prompt Injection

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `indirect_injection` |
| **Description** | Adversarial instructions embedded in external data sources (web pages, documents, emails, API responses) that the agent retrieves and processes. |
| **Prerequisites** | Agent retrieves and processes external data. Attacker can influence content of external data sources. |
| **Attack Vector** | Hidden text in HTML (CSS `display:none`, white-on-white), document metadata fields, email signatures, code comments, spreadsheet formulas, image alt text, JSON field injection. |
| **Impact** | Goal hijacking, data exfiltration, unauthorized actions, information disclosure. |
| **Severity** | High to Critical |
| **MITRE ATLAS** | AML.T0051.001 -- LLM Prompt Injection: Indirect |
| **OWASP LLM** | LLM01 -- Prompt Injection |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |
| **Mitigations** | Sanitize external data before inclusion in context. Use separate processing pipelines for instructions and data. Implement content security policies. Limit agent context window. |

#### PI-02: Tool Output Injection

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `tool_output_injection` |
| **Description** | Malicious payloads injected into tool return values that are processed by the agent as trusted context. |
| **Prerequisites** | Agent calls tools whose output is attacker-controllable (e.g., web search, API calls). |
| **Attack Vector** | Crafted API responses, poisoned search results, manipulated database records. |
| **Impact** | Goal hijacking, privilege escalation, data exfiltration. |
| **Severity** | Critical |
| **MITRE ATLAS** | AML.T0051.001 |
| **OWASP LLM** | LLM01 -- Prompt Injection |
| **CWE** | CWE-94 |
| **Mitigations** | Treat all tool outputs as untrusted. Validate and sanitize tool return values. Use structured output parsing instead of free-text. |

#### PI-03: Context Poisoning

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `context_poisoning` |
| **Description** | Gradually corrupting the agent's conversation context to alter its behavior over time. |
| **Prerequisites** | Ability to inject content into the agent's context across multiple turns. |
| **Attack Vector** | Multi-turn manipulation, context window overflow, instruction drift. |
| **Impact** | Behavioral change, policy violation, unauthorized actions. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM01 -- Prompt Injection |
| **CWE** | CWE-94 |
| **Mitigations** | Implement context integrity verification. Use sliding window with periodic re-anchoring to system prompt. Monitor for behavioral drift. |

### 5.2 Tool Manipulation (TM)

Tool manipulation attacks exploit the interface between the LLM decision-maker
and the tools it invokes.

#### TM-01: Parameter Injection

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `parameter_injection` |
| **Description** | Injecting malicious values into tool call parameters, analogous to SQL injection, path traversal, SSRF, and command injection in traditional applications. |
| **Prerequisites** | Agent passes user-influenced data to tool parameters. Tool does not validate inputs. |
| **Attack Vector** | SQL injection via database query tools, path traversal via file access tools, SSRF via HTTP request tools, command injection via code execution tools. |
| **Impact** | Data breach, remote code execution, internal network access. |
| **Severity** | High to Critical |
| **MITRE ATLAS** | AML.T0040 -- ML Supply Chain Compromise |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-89 (SQLi), CWE-22 (Path Traversal), CWE-918 (SSRF), CWE-78 (Command Injection) |
| **Mitigations** | Parameterized queries for all database tools. Allow-list paths for file tools. URL validation and allow-listing for HTTP tools. Sandboxed execution for code tools. |

#### TM-02: Schema Abuse

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `schema_abuse` |
| **Description** | Exploiting weaknesses in tool schema definitions to pass unexpected parameter types, additional parameters, or bypass validation. |
| **Prerequisites** | Tool schema does not use strict validation. Agent does not enforce schema before calling tools. |
| **Attack Vector** | Type confusion, additional property injection, default value exploitation, nested object manipulation. |
| **Impact** | Unexpected tool behavior, security policy bypass. |
| **Severity** | Medium |
| **MITRE ATLAS** | AML.T0040 |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-20 (Improper Input Validation) |
| **Mitigations** | Strict JSON Schema validation with `additionalProperties: false`. Type checking on all parameters. Server-side schema enforcement independent of LLM. |

#### TM-03: Tool Confusion

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `tool_confusion` |
| **Description** | Tricking the agent into calling the wrong tool by manipulating context or exploiting ambiguous tool descriptions. |
| **Prerequisites** | Multiple tools with overlapping functionality. Tool descriptions that can be misinterpreted. |
| **Attack Vector** | Ambiguous requests that match multiple tools, context manipulation to bias tool selection. |
| **Impact** | Unintended side effects, data sent to wrong destination, privilege escalation. |
| **Severity** | Medium |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-345 (Insufficient Verification of Data Authenticity) |
| **Mitigations** | Clear, non-overlapping tool descriptions. Confirmation prompts for high-risk operations. Tool call auditing. |

#### TM-04: Chain Exploitation

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `chain_exploitation` |
| **Description** | Multi-step attack that chains multiple tool calls together, where each step is individually benign but the combination achieves a malicious outcome. |
| **Prerequisites** | Agent has access to multiple tools. No cross-tool authorization checks. |
| **Attack Vector** | Read credentials from config file, then use them to access a restricted API. List users, then escalate to admin via a separate tool. |
| **Impact** | Complex privilege escalation, multi-step data exfiltration. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **Mitigations** | Cross-tool authorization policies. Session-level permission tracking. Anomaly detection on tool call sequences. |

### 5.3 Privilege Escalation (PE)

Privilege escalation attacks exploit gaps in the authorization model of the
agentic system.

#### PE-01: Permission Bypass

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `permission_bypass` |
| **Description** | Circumventing tool permission boundaries by manipulating the agent's understanding of its own permissions. |
| **Prerequisites** | Permission model relies on LLM self-enforcement rather than hard system boundaries. |
| **Attack Vector** | Instructing the agent that it has admin privileges, claiming an override code, social-engineering the agent to ignore permission checks. |
| **Impact** | Unauthorized access to restricted tools and data. |
| **Severity** | Critical |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM08 -- Excessive Agency |
| **CWE** | CWE-285 (Improper Authorization) |
| **Mitigations** | Hard-coded permission boundaries enforced at the tool layer, not the LLM layer. System-level access control independent of agent context. |

#### PE-02: Scope Expansion

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `scope_expansion` |
| **Description** | Gradually expanding the agent's operational scope beyond its intended boundaries. |
| **Prerequisites** | Agent's scope is defined by instructions that can be influenced. |
| **Attack Vector** | Multi-turn scope creep, task redefinition, capability discovery prompts. |
| **Impact** | Agent operates outside its intended domain. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM08 -- Excessive Agency |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **Mitigations** | Hard scope boundaries at the system level. Tool allow-listing. Monitoring for out-of-scope tool calls. |

#### PE-03: Cross-Tool Escalation

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `cross_tool_escalation` |
| **Description** | Using the output of one tool as input to another to achieve privilege escalation that neither tool would permit individually. |
| **Prerequisites** | Agent has access to multiple tools with different privilege levels. No cross-tool data flow controls. |
| **Attack Vector** | Reading credentials from a low-privilege tool (file reader) and passing them to a high-privilege tool (API caller). |
| **Impact** | Full privilege escalation, lateral movement. |
| **Severity** | Critical |
| **MITRE ATLAS** | AML.T0040 |
| **OWASP LLM** | LLM08 -- Excessive Agency |
| **CWE** | CWE-269 |
| **Mitigations** | Data flow controls between tools. Taint tracking on tool outputs. Principle of least privilege per tool. |

### 5.4 Multi-Agent Attacks (MA)

Multi-agent attacks target systems where multiple LLM agents communicate and
collaborate.

#### MA-01: Agent Impersonation

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `agent_impersonation` |
| **Description** | Impersonating a trusted agent in a multi-agent system to gain access or influence behavior. |
| **Prerequisites** | Multi-agent system with message-based communication. Weak or absent agent authentication. |
| **Attack Vector** | Spoofed agent identity in messages, replay of legitimate agent messages, agent name collision. |
| **Impact** | Unauthorized instructions accepted as legitimate, data exfiltration via trusted channel. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM09 -- Overreliance |
| **CWE** | CWE-287 (Improper Authentication) |
| **Mitigations** | Cryptographic agent authentication. Message signing. Agent registry with identity verification. |

#### MA-02: Message Tampering

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `message_tampering` |
| **Description** | Modifying inter-agent messages to alter instructions, inject payloads, or corrupt shared context. |
| **Prerequisites** | Inter-agent messages pass through controllable channels. No message integrity verification. |
| **Attack Vector** | Man-in-the-middle on agent communication, injection into shared memory/context stores. |
| **Impact** | Corrupted agent behavior, cascading failures across agents. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM01 -- Prompt Injection |
| **CWE** | CWE-345 (Insufficient Verification of Data Authenticity) |
| **Mitigations** | Message integrity verification (HMAC, signatures). End-to-end encryption between agents. Immutable message logs. |

#### MA-03: Trust Exploitation

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `trust_exploitation` |
| **Description** | Exploiting implicit trust relationships between agents to escalate privileges or bypass security controls. |
| **Prerequisites** | Agents trust messages from peer agents without independent verification. |
| **Attack Vector** | Compromising one agent to issue commands to trusted peers. Exploiting delegation chains. |
| **Impact** | Cascading compromise across the multi-agent system. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM09 -- Overreliance |
| **CWE** | CWE-862 (Missing Authorization) |
| **Mitigations** | Zero-trust between agents. Independent authorization checks per agent. Delegation audit trails. |

### 5.5 MCP-Specific Attacks (MCP)

MCP attacks target the Model Context Protocol, an emerging standard for
connecting LLM agents to external tool servers.

#### MCP-01: Tool Shadowing

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `mcp_tool_shadowing` |
| **Description** | A malicious MCP server registers tools that shadow (override) legitimate tools by using identical or similar names, intercepting calls meant for trusted servers. |
| **Prerequisites** | Agent connects to multiple MCP servers. No tool name uniqueness enforcement or server pinning. |
| **Attack Vector** | Exact name collision, similar name registration, tool version spoofing, proxy tool injection, deprecation-based redirection. |
| **Impact** | Tool call interception, data exfiltration, response manipulation. |
| **Severity** | Critical |
| **MITRE ATLAS** | AML.T0051 |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-349 (Acceptance of Extraneous Untrusted Data) |
| **Mitigations** | Tool name uniqueness enforcement across MCP servers. Tool version pinning with integrity hashes. Explicit server-tool binding. Alert on registration conflicts. |

#### MCP-02: Capability Abuse

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `mcp_capability_abuse` |
| **Description** | Exploiting MCP capability negotiation to gain access to resources or operations beyond what the server should provide. |
| **Prerequisites** | MCP server does not strictly validate capability requests. |
| **Attack Vector** | Requesting undeclared capabilities, capability escalation via renegotiation, exploiting capability caching. |
| **Impact** | Access to unauthorized resources, elevated permissions. |
| **Severity** | High |
| **MITRE ATLAS** | AML.T0040 |
| **OWASP LLM** | LLM07 -- Insecure Plugin Design |
| **CWE** | CWE-285 (Improper Authorization) |
| **Mitigations** | Strict server-side capability validation. Immutable capability grants. Capability audit logging. |

#### MCP-03: Malicious Server

| Field | Value |
|-------|-------|
| **AgentPwn Module** | `mcp_malicious_server` |
| **Description** | Simulating a fully malicious MCP server that provides manipulated tool outputs, exfiltrates data from tool call parameters, or injects payloads. |
| **Prerequisites** | Agent connects to an MCP server controlled by an attacker. |
| **Attack Vector** | Man-in-the-middle, DNS hijacking, supply chain compromise of MCP server packages. |
| **Impact** | Full compromise of agent behavior, data exfiltration, remote code execution via manipulated tool outputs. |
| **Severity** | Critical |
| **MITRE ATLAS** | AML.T0040 |
| **OWASP LLM** | LLM05 -- Supply Chain Vulnerabilities |
| **CWE** | CWE-494 (Download of Code Without Integrity Check) |
| **Mitigations** | MCP server authentication and TLS verification. Server allow-listing. Tool output validation. Sandboxed execution of tool results. |

---

## 6. Risk Scoring Methodology

AgentPwn computes a risk score (0--100) for each campaign based on the findings.

### 6.1 Severity Weights

| Severity | Weight | Rationale |
|----------|--------|-----------|
| Critical | 40 | Immediate exploitation risk; full compromise possible. |
| High | 25 | Significant exploitation risk; major impact without full compromise. |
| Medium | 15 | Moderate risk; exploitation requires specific conditions. |
| Low | 5 | Minor risk; limited impact or difficult to exploit. |
| Info | 1 | Informational; no direct exploitation risk. |

### 6.2 Score Computation

```
raw_score = sum(weight[severity] * count[severity] for each severity)
risk_score = min(raw_score, 100)
```

### 6.3 Risk Levels

| Score | Level | Interpretation |
|-------|-------|----------------|
| 0--4 | Minimal | No significant findings. Agent demonstrates strong security posture. |
| 5--24 | Low | Minor issues found. Address in regular development cycle. |
| 25--49 | Medium | Moderate vulnerabilities. Prioritize remediation before production deployment. |
| 50--74 | High | Serious vulnerabilities. Do not deploy without remediation. |
| 75--100 | Critical | Critical vulnerabilities. Immediate action required. System is exploitable. |

---

## 7. Standards Mapping

### 7.1 MITRE ATLAS Mapping

| AgentPwn Category | ATLAS Technique |
|-------------------|-----------------|
| Prompt Injection | AML.T0051 -- LLM Prompt Injection |
| Indirect Prompt Injection | AML.T0051.001 -- LLM Prompt Injection: Indirect |
| Tool Manipulation | AML.T0040 -- ML Supply Chain Compromise |
| Multi-Agent Attacks | AML.T0051 -- LLM Prompt Injection |

### 7.2 OWASP LLM Top 10 (2025) Mapping

| AgentPwn Category | OWASP Entry |
|-------------------|-------------|
| Prompt Injection (PI-01, PI-02, PI-03) | LLM01 -- Prompt Injection |
| Tool Manipulation (TM-01, TM-02, TM-03) | LLM07 -- Insecure Plugin Design |
| Tool Chain Exploitation (TM-04) | LLM07 -- Insecure Plugin Design |
| Privilege Escalation (PE-01, PE-02, PE-03) | LLM08 -- Excessive Agency |
| Multi-Agent Trust (MA-01, MA-03) | LLM09 -- Overreliance |
| MCP Attacks (MCP-01, MCP-02, MCP-03) | LLM05 -- Supply Chain Vulnerabilities, LLM07 -- Insecure Plugin Design |

---

## 8. References

- MITRE ATLAS: <https://atlas.mitre.org/>
- OWASP LLM Top 10: <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- Model Context Protocol: <https://modelcontextprotocol.io/>
- NIST AI Risk Management Framework: <https://www.nist.gov/artificial-intelligence>

---

*This threat model is maintained alongside the AgentPwn source code. As new
vulnerability classes are discovered and new attack modules are added, this
document is updated to reflect the expanded taxonomy.*
