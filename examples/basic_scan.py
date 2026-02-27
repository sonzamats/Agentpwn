# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0

"""Basic scan example.

Demonstrates the simplest way to run an AgentPwn security scan:
load a campaign configuration, execute it, and display results.
"""

from __future__ import annotations

import asyncio

from agentpwn.core.config import load_campaign_config
from agentpwn.core.engine import CampaignEngine


async def main() -> None:
    # ------------------------------------------------------------------
    # Step 1: Load the campaign configuration from a YAML file.
    #
    # The config describes the target agent (type, model, tools, auth)
    # and the attack parameters (which modules, timeouts, report formats).
    # API keys are resolved from environment variables automatically.
    # ------------------------------------------------------------------
    config = load_campaign_config("campaigns/quick_scan.yaml")

    # ------------------------------------------------------------------
    # Step 2: Create the campaign engine.
    #
    # The engine orchestrates the entire scan: it loads the target
    # connector, discovers attack modules, runs them, and collects
    # results. The report_dir is where output files will be written.
    # ------------------------------------------------------------------
    engine = CampaignEngine(config, report_dir="./reports")

    # ------------------------------------------------------------------
    # Step 3: Initialize the engine.
    #
    # This connects to the target agent and discovers available attack
    # modules. If specific modules are listed in the config, only those
    # are loaded; otherwise all modules are used.
    # ------------------------------------------------------------------
    await engine.initialize()

    # ------------------------------------------------------------------
    # Step 4: Run the campaign.
    #
    # Each attack module generates payloads and delivers them to the
    # target via the target connector. Results are collected and a
    # CampaignReport is returned with findings, risk score, and summary.
    # ------------------------------------------------------------------
    report = await engine.run()

    # ------------------------------------------------------------------
    # Step 5: Display results.
    #
    # The engine can render a Rich terminal table summarizing findings
    # by module, payload count, and severity. Full reports are also
    # written to the report directory in JSON and Markdown formats.
    # ------------------------------------------------------------------
    engine.display_results_table(report)

    # ------------------------------------------------------------------
    # Step 6: Inspect results programmatically.
    # ------------------------------------------------------------------
    print(f"\nRisk Score: {report.risk_score:.1f}/100")
    print(f"Total attacks: {report.total_attacks}")
    print(f"Successful attacks: {report.successful_attacks}")
    print(f"Critical findings: {report.summary.critical_findings}")
    print(f"High findings: {report.summary.high_findings}")

    # Print each successful finding
    for result in report.results:
        if result.success:
            print(f"\n  [{result.severity.value.upper()}] {result.attack_module}")
            print(f"    {result.description}")
            if result.evidence:
                print(f"    Evidence: {result.evidence.details[:200]}")


if __name__ == "__main__":
    asyncio.run(main())
