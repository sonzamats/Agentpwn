# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pydantic v2 data models for AgentPwn.

Defines the core data structures used throughout the framework including
target configurations, attack results, evidence records, and campaign
reports. All models use strict validation and are serializable to JSON
for logging and reporting.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class TargetType(str, Enum):
    """Supported agent framework types."""

    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    OPENAI_FUNCTIONS = "openai_functions"
    ANTHROPIC_TOOLS = "anthropic_tools"
    MCP = "mcp"
    CUSTOM = "custom"


class RiskLevel(str, Enum):
    """Risk classification for tools and findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(str, Enum):
    """Severity of a security finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceType(str, Enum):
    """Classification of attack evidence."""

    DATA_EXFILTRATION = "data_exfiltration"
    GOAL_HIJACKING = "goal_hijacking"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    INFORMATION_DISCLOSURE = "information_disclosure"


class ReportFormat(str, Enum):
    """Supported report output formats."""

    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


class AttackCategory(str, Enum):
    """Top-level attack category taxonomy."""

    PROMPT_INJECTION = "prompt_injection"
    TOOL_MANIPULATION = "tool_manipulation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MULTI_AGENT = "multi_agent"
    MCP_ATTACKS = "mcp_attacks"


class MessageRole(str, Enum):
    """Role of a message in a conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class VulnerabilityLevel(str, Enum):
    """Simulated vulnerability level for mock targets."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------


class AuthConfig(BaseModel):
    """Authentication configuration for connecting to a target agent."""

    api_key: str | None = Field(default=None, description="API key for authentication")
    bearer_token: str | None = Field(default=None, description="Bearer token")
    headers: dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    oauth_config: dict[str, Any] | None = Field(
        default=None, description="OAuth2 configuration"
    )


class ToolDefinition(BaseModel):
    """Describes a tool available to the target agent.

    Used to map the agent's attack surface and identify potential
    escalation paths between tools.
    """

    name: str = Field(description="Tool name as registered with the agent")
    description: str = Field(description="Human-readable description of the tool's purpose")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="JSON Schema for the tool's parameters"
    )
    permissions: list[str] = Field(
        default_factory=list,
        description="Permission tags: read, write, execute, network, etc.",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM, description="Assessed risk level of this tool"
    )


class TargetConfig(BaseModel):
    """Configuration describing the agent system under test.

    This is the primary input to a campaign: it tells AgentPwn what
    kind of agent it's testing, how to connect, and what tools the
    agent has access to.
    """

    name: str = Field(description="Human-readable name for this target")
    target_type: TargetType = Field(description="Agent framework type")
    endpoint: str | None = Field(
        default=None, description="API endpoint URL for remote agents"
    )
    model: str | None = Field(
        default=None, description="LLM model identifier (e.g. gpt-4, claude-sonnet-4-20250514)"
    )
    tools: list[ToolDefinition] = Field(
        default_factory=list, description="Tools available to the agent"
    )
    system_prompt: str | None = Field(
        default=None, description="Agent system prompt, if known"
    )
    auth: AuthConfig | None = Field(
        default=None, description="Authentication configuration"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary metadata about the target"
    )


class Message(BaseModel):
    """A single message in a conversation history."""

    role: MessageRole = Field(description="Who sent this message")
    content: str = Field(description="Message content")
    tool_call_id: str | None = Field(default=None, description="Associated tool call ID")
    name: str | None = Field(default=None, description="Name of the tool or function")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this message was created",
    )


class ToolCallRecord(BaseModel):
    """Record of a single tool call made by an agent.

    Captures both the request (what the agent asked for) and the
    response (what it got back), enabling analysis of parameter
    injection and unauthorized tool use.
    """

    tool_call_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this tool call",
    )
    tool_name: str = Field(description="Name of the tool that was called")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Arguments passed to the tool"
    )
    result: str | None = Field(default=None, description="Result returned by the tool")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this call was made",
    )
    was_injected: bool = Field(
        default=False,
        description="Whether this tool output was injected by AgentPwn",
    )


class AgentResponse(BaseModel):
    """The full response from an agent after an interaction.

    Captures the agent's text reply, any tool calls it made, and
    the raw response for forensic analysis.
    """

    content: str = Field(description="Agent's text response")
    tool_calls: list[ToolCallRecord] = Field(
        default_factory=list, description="Tool calls made during this interaction"
    )
    raw_response: dict[str, Any] | None = Field(
        default=None, description="Raw API response for forensic analysis"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this response was received",
    )


class Payload(BaseModel):
    """An attack payload to be delivered to a target agent.

    Payloads are the atomic unit of attacks — each one represents a
    specific adversarial input designed to trigger a vulnerability.
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier",
    )
    name: str = Field(description="Short descriptive name")
    content: str = Field(description="The payload content to be injected")
    category: AttackCategory = Field(description="Which attack category this belongs to")
    description: str = Field(description="What this payload attempts to do")
    expected_behavior: str = Field(
        description="What behavior indicates the attack succeeded"
    )
    severity: Severity = Field(
        default=Severity.HIGH, description="Severity if this payload succeeds"
    )
    tags: list[str] = Field(default_factory=list, description="Searchable tags")


class Evidence(BaseModel):
    """Proof that an attack succeeded against a target agent.

    Evidence is the critical output of an attack: it documents exactly
    what happened and why it constitutes a security finding.
    """

    type: EvidenceType = Field(description="Classification of the evidence")
    details: str = Field(description="Human-readable description of what happened")
    artifacts: list[str] = Field(
        default_factory=list,
        description="Paths to supporting files (logs, screenshots, etc.)",
    )


class AttackConfig(BaseModel):
    """Per-module configuration for running an attack."""

    max_attempts: int = Field(default=10, description="Maximum payload attempts")
    timeout_seconds: int = Field(default=60, description="Timeout per attempt in seconds")
    delay_between_attempts: float = Field(
        default=1.0, description="Seconds to wait between attempts"
    )
    custom_payloads: list[Payload] = Field(
        default_factory=list, description="Additional user-supplied payloads"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Module-specific configuration"
    )


class AttackResult(BaseModel):
    """The result of a single attack attempt against a target.

    This is the primary output of an attack module: it records whether
    the attack succeeded, what happened, and what should be done about it.
    """

    attack_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this result",
    )
    attack_module: str = Field(description="Module that generated this result")
    attack_category: str = Field(description="Top-level attack category")
    target: str = Field(description="Name of the target that was attacked")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this result was produced",
    )
    success: bool = Field(description="Whether the attack achieved its objective")
    severity: Severity = Field(description="Severity of the finding")
    description: str = Field(description="What was tested and what happened")
    evidence: Evidence | None = Field(
        default=None, description="Proof of exploitation, if attack succeeded"
    )
    payload_used: str = Field(default="", description="The payload that was used")
    agent_response: str = Field(default="", description="The agent's response to the payload")
    tool_calls_made: list[ToolCallRecord] = Field(
        default_factory=list, description="Tool calls observed during the attack"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Remediation recommendations"
    )


class CampaignConfig(BaseModel):
    """Defines a full red-team campaign.

    A campaign is a collection of attack modules run against a target.
    This config controls which modules run, how many attempts each gets,
    and how results are reported.
    """

    name: str = Field(description="Campaign name")
    description: str = Field(default="", description="Campaign description")
    target: TargetConfig = Field(description="The target agent to test")
    attack_modules: list[str] = Field(
        default_factory=list,
        description="Module names to run (empty = all available modules)",
    )
    max_attempts_per_module: int = Field(
        default=10, description="Max payload attempts per module"
    )
    timeout_seconds: int = Field(
        default=300, description="Timeout for the entire campaign in seconds"
    )
    parallel: bool = Field(
        default=False, description="Whether to run modules concurrently"
    )
    report_formats: list[ReportFormat] = Field(
        default_factory=lambda: [ReportFormat.JSON, ReportFormat.MARKDOWN],
        description="Output formats for the campaign report",
    )
    permission_confirmed: bool = Field(
        default=False,
        description="User has confirmed they have permission to test this target",
    )


class CampaignSummary(BaseModel):
    """High-level statistics from a campaign run."""

    total_modules_run: int = Field(default=0, description="Number of attack modules executed")
    critical_findings: int = Field(default=0, description="Count of critical findings")
    high_findings: int = Field(default=0, description="Count of high findings")
    medium_findings: int = Field(default=0, description="Count of medium findings")
    low_findings: int = Field(default=0, description="Count of low findings")
    info_findings: int = Field(default=0, description="Count of informational findings")
    categories_tested: list[str] = Field(
        default_factory=list, description="Attack categories that were tested"
    )
    most_vulnerable_category: str = Field(
        default="none", description="Category with the most findings"
    )


class CampaignReport(BaseModel):
    """Complete report from a campaign run.

    Contains all results, summary statistics, and a computed risk
    score that represents the overall security posture of the target.
    """

    campaign_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this campaign run",
    )
    campaign_name: str = Field(description="Name of the campaign")
    target: TargetConfig = Field(description="The target that was tested")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the campaign started",
    )
    completed_at: datetime | None = Field(
        default=None, description="When the campaign finished"
    )
    total_attacks: int = Field(default=0, description="Total attack attempts made")
    successful_attacks: int = Field(
        default=0, description="Number of attacks that succeeded"
    )
    results: list[AttackResult] = Field(
        default_factory=list, description="All individual attack results"
    )
    summary: CampaignSummary = Field(
        default_factory=CampaignSummary, description="Aggregate statistics"
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Overall risk score from 0 (secure) to 100 (critical)",
    )

    def compute_summary(self) -> None:
        """Recompute the summary and risk score from current results.

        Called after all attacks have been run to produce final statistics.
        The risk score is a weighted sum: critical findings contribute more
        than low findings.
        """
        successful = [r for r in self.results if r.success]
        self.total_attacks = len(self.results)
        self.successful_attacks = len(successful)

        severity_counts: dict[Severity, int] = {s: 0 for s in Severity}
        category_counts: dict[str, int] = {}
        categories_seen: set[str] = set()

        for result in successful:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
            category_counts[result.attack_category] = (
                category_counts.get(result.attack_category, 0) + 1
            )

        for result in self.results:
            categories_seen.add(result.attack_category)

        self.summary = CampaignSummary(
            total_modules_run=len({r.attack_module for r in self.results}),
            critical_findings=severity_counts.get(Severity.CRITICAL, 0),
            high_findings=severity_counts.get(Severity.HIGH, 0),
            medium_findings=severity_counts.get(Severity.MEDIUM, 0),
            low_findings=severity_counts.get(Severity.LOW, 0),
            info_findings=severity_counts.get(Severity.INFO, 0),
            categories_tested=sorted(categories_seen),
            most_vulnerable_category=(
                max(category_counts, key=category_counts.get)  # type: ignore[arg-type]
                if category_counts
                else "none"
            ),
        )

        # Weighted risk score: critical=40, high=25, medium=15, low=5, info=1
        weights = {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 25.0,
            Severity.MEDIUM: 15.0,
            Severity.LOW: 5.0,
            Severity.INFO: 1.0,
        }
        raw_score = sum(
            weights.get(sev, 0) * count for sev, count in severity_counts.items()
        )
        # Normalize to 0-100 range (cap at 100)
        self.risk_score = min(100.0, raw_score)
