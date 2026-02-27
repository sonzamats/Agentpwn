# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0

"""MCP security audit example.

Demonstrates how to run a focused security audit against an agent
connected to MCP (Model Context Protocol) servers. This example
targets the MCP-specific attack surface: tool shadowing, capability
abuse, and malicious server simulation.
"""

from __future__ import annotations

import asyncio

from agentpwn.core.config import load_campaign_config
from agentpwn.core.engine import CampaignEngine
from agentpwn.core.models import (
    AuthConfig,
    CampaignConfig,
    ReportFormat,
    TargetConfig,
    TargetType,
    ToolDefinition,
)


async def run_from_yaml() -> None:
    """Run an MCP audit using the pre-built campaign config."""

    # ------------------------------------------------------------------
    # The simplest approach: use the mcp_focused campaign config.
    # This config targets MCP-specific attack modules only.
    # ------------------------------------------------------------------
    config = load_campaign_config("campaigns/mcp_focused.yaml")

    engine = CampaignEngine(config, report_dir="./reports/mcp_audit")
    report = await engine.run()
    engine.display_results_table(report)

    # Summarize MCP-specific findings
    mcp_results = [
        r for r in report.results
        if r.attack_category == "mcp_attacks"
    ]
    print(f"\nMCP attack results: {len(mcp_results)} payloads tested")
    print(f"MCP findings: {sum(1 for r in mcp_results if r.success)}")


async def run_programmatic() -> None:
    """Run an MCP audit using programmatic configuration.

    This approach is useful when you want to dynamically configure
    the audit based on runtime conditions, or when you need to test
    against MCP servers that are spun up as part of a CI/CD pipeline.
    """

    # ------------------------------------------------------------------
    # Step 1: Define the target configuration.
    #
    # For MCP targets, the key fields are:
    #   - target_type: must be "mcp"
    #   - endpoint: the MCP server URL
    #   - tools: the tools exposed by the MCP server
    # ------------------------------------------------------------------
    target_config = TargetConfig(
        name="my-mcp-agent",
        target_type=TargetType.MCP,
        endpoint="http://localhost:8080/mcp",
        model="gpt-4",
        tools=[
            ToolDefinition(
                name="web_search",
                description="Search the web for information",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                permissions=["network"],
                risk_level="medium",
            ),
            ToolDefinition(
                name="read_file",
                description="Read a file from the filesystem",
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
                permissions=["read"],
                risk_level="high",
            ),
            ToolDefinition(
                name="database_query",
                description="Execute a SQL query",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                permissions=["read", "write"],
                risk_level="high",
            ),
            ToolDefinition(
                name="send_email",
                description="Send an email",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                },
                permissions=["network", "write"],
                risk_level="high",
            ),
        ],
        auth=AuthConfig(api_key=None),  # Resolved from env vars
    )

    # ------------------------------------------------------------------
    # Step 2: Build the campaign configuration.
    #
    # For an MCP-focused audit, restrict attack_modules to MCP modules.
    # You can also include prompt_injection and tool_manipulation modules
    # since MCP agents are vulnerable to those as well.
    # ------------------------------------------------------------------
    campaign_config = CampaignConfig(
        name="mcp-security-audit",
        description="Focused MCP security audit",
        target=target_config,
        attack_modules=[
            # MCP-specific attacks
            "mcp_tool_shadowing",
            "mcp_capability_abuse",
            "mcp_malicious_server",
            # Cross-cutting attacks that also apply to MCP
            "tool_output_injection",
            "parameter_injection",
        ],
        max_attempts_per_module=10,
        timeout_seconds=300,
        parallel=False,
        report_formats=[ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.HTML],
        permission_confirmed=True,  # You MUST have authorization
    )

    # ------------------------------------------------------------------
    # Step 3: Run the audit.
    # ------------------------------------------------------------------
    engine = CampaignEngine(campaign_config, report_dir="./reports/mcp_audit")
    report = await engine.run()
    engine.display_results_table(report)

    # ------------------------------------------------------------------
    # Step 4: Analyze MCP-specific findings.
    # ------------------------------------------------------------------
    print("\n--- MCP Audit Summary ---")
    print(f"Risk Score: {report.risk_score:.1f}/100")

    for result in report.results:
        if result.success:
            print(f"\n  [{result.severity.value.upper()}] {result.attack_module}")
            print(f"    {result.description}")
            if result.recommendations:
                print("    Recommendations:")
                for rec in result.recommendations:
                    print(f"      - {rec}")


if __name__ == "__main__":
    # Choose which approach to use:
    # asyncio.run(run_from_yaml())      # Use the pre-built YAML config
    asyncio.run(run_programmatic())      # Use programmatic configuration
