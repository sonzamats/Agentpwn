# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0

"""MCP-specific security audit example.

Demonstrates how to configure an MCP target and run only the MCP attack
modules (mcp_malicious_server, mcp_tool_shadowing, mcp_capability_abuse).
Generates an HTML report of findings.

Usage:
    python examples/mcp_audit.py

Before running, ensure you have:
    1. An MCP-enabled agent available at the configured endpoint.
    2. Set permission_confirmed to True after confirming authorization.
"""

from __future__ import annotations

import asyncio

from agentpwn.core.engine import CampaignEngine
from agentpwn.core.models import (
    AuthConfig,
    CampaignConfig,
    ReportFormat,
    TargetConfig,
    TargetType,
    ToolDefinition,
    RiskLevel,
)


# -----------------------------------------------------------------------
# MCP attack module names (must match the `name` attribute in each class)
# -----------------------------------------------------------------------
MCP_MODULES = [
    "mcp_malicious_server",
    "mcp_tool_shadowing",
    "mcp_capability_abuse",
]


async def main() -> None:
    """Configure an MCP target, run MCP attacks, and generate an HTML report."""

    # ------------------------------------------------------------------
    # 1. Define the MCP target
    # ------------------------------------------------------------------
    target = TargetConfig(
        name="my-mcp-agent",
        target_type=TargetType.MCP,
        endpoint="http://localhost:3000/mcp",
        model="gpt-4",
        tools=[
            ToolDefinition(
                name="web_search",
                description="Search the web via MCP tool server",
                parameters={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                permissions=["network"],
                risk_level=RiskLevel.MEDIUM,
            ),
            ToolDefinition(
                name="file_read",
                description="Read files from the filesystem via MCP",
                parameters={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
                permissions=["read"],
                risk_level=RiskLevel.HIGH,
            ),
            ToolDefinition(
                name="send_email",
                description="Send email via MCP tool server",
                parameters={
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                },
                permissions=["network", "write"],
                risk_level=RiskLevel.HIGH,
            ),
        ],
        system_prompt="You are a helpful assistant with access to MCP tools.",
        auth=AuthConfig(),
    )

    # ------------------------------------------------------------------
    # 2. Build the campaign config -- MCP modules only, HTML report
    # ------------------------------------------------------------------
    campaign = CampaignConfig(
        name="mcp-security-audit",
        description=(
            "Targeted audit of MCP-specific attack vectors including "
            "malicious server responses, tool shadowing, and capability abuse."
        ),
        target=target,
        attack_modules=MCP_MODULES,
        max_attempts_per_module=10,
        timeout_seconds=300,
        parallel=False,
        report_formats=[ReportFormat.HTML],
        permission_confirmed=False,  # Set to True when you have authorization
    )

    # ------------------------------------------------------------------
    # 3. Run the campaign
    # ------------------------------------------------------------------
    engine = CampaignEngine(campaign, report_dir="./reports")

    print("=" * 60)
    print("  AgentPwn -- MCP Security Audit")
    print("=" * 60)
    print(f"  Target   : {target.name}")
    print(f"  Endpoint : {target.endpoint}")
    print(f"  Tools    : {', '.join(t.name for t in target.tools)}")
    print(f"  Modules  : {', '.join(MCP_MODULES)}")
    print("=" * 60)
    print()

    await engine.initialize()

    print(f"Loaded {len(engine.attack_modules)} MCP attack module(s).\n")
    report = await engine.run()

    # ------------------------------------------------------------------
    # 4. Display results
    # ------------------------------------------------------------------
    engine.display_results_table(report)

    print(f"\nTotal attacks : {report.total_attacks}")
    print(f"Successful    : {report.successful_attacks}")
    print(f"Risk score    : {report.risk_score:.1f} / 100")
    print(f"\nHTML report written to: ./reports/")

    # Breakdown by MCP module
    if report.successful_attacks > 0:
        print("\nFindings by module:")
        module_findings: dict[str, int] = {}
        for result in report.results:
            if result.success:
                module_findings[result.attack_module] = (
                    module_findings.get(result.attack_module, 0) + 1
                )
        for module_name, count in sorted(
            module_findings.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {module_name}: {count} finding(s)")


if __name__ == "__main__":
    asyncio.run(main())
