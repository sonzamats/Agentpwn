# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0

"""Full campaign example.

Demonstrates a comprehensive security audit workflow:
1. Load and validate configuration.
2. Run all attack modules against the target.
3. Generate reports in all formats (JSON, Markdown, HTML).
4. Perform post-campaign analysis.
5. Export findings for integration with external tools.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from agentpwn.core.config import load_campaign_config, validate_config
from agentpwn.core.engine import CampaignEngine
from agentpwn.core.models import CampaignReport, Severity


# ======================================================================
# Configuration and Validation
# ======================================================================


def validate_campaign(config_path: str) -> bool:
    """Validate a campaign configuration before running.

    Returns True if the config is valid, False otherwise.
    Prints any validation errors to stderr.
    """
    errors = validate_config(config_path)
    if errors:
        print("Configuration errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return False
    print("Configuration is valid.")
    return True


# ======================================================================
# Post-Campaign Analysis
# ======================================================================


def analyze_report(report: CampaignReport) -> dict:
    """Perform detailed analysis of campaign results.

    Returns a structured analysis dictionary suitable for integration
    with external security tools and dashboards.
    """
    # Group findings by category
    findings_by_category: dict[str, list] = {}
    for result in report.results:
        if result.success:
            cat = result.attack_category
            if cat not in findings_by_category:
                findings_by_category[cat] = []
            findings_by_category[cat].append({
                "module": result.attack_module,
                "severity": result.severity.value,
                "description": result.description,
                "evidence": result.evidence.details if result.evidence else None,
                "recommendations": result.recommendations,
            })

    # Compute category-level risk
    category_risk: dict[str, dict] = {}
    severity_weights = {
        Severity.CRITICAL: 40, Severity.HIGH: 25,
        Severity.MEDIUM: 15, Severity.LOW: 5, Severity.INFO: 1,
    }
    for cat, findings in findings_by_category.items():
        total_weight = sum(
            severity_weights.get(Severity(f["severity"]), 0)
            for f in findings
        )
        category_risk[cat] = {
            "findings_count": len(findings),
            "risk_weight": total_weight,
            "max_severity": max(
                (f["severity"] for f in findings),
                key=lambda s: severity_weights.get(Severity(s), 0),
            ),
        }

    # Compile the analysis
    analysis = {
        "campaign_id": report.campaign_id,
        "campaign_name": report.campaign_name,
        "target": report.target.name,
        "target_type": report.target.target_type.value,
        "model": report.target.model,
        "risk_score": report.risk_score,
        "total_attacks": report.total_attacks,
        "successful_attacks": report.successful_attacks,
        "success_rate": (
            report.successful_attacks / report.total_attacks * 100
            if report.total_attacks > 0
            else 0.0
        ),
        "findings_by_category": findings_by_category,
        "category_risk": category_risk,
        "most_vulnerable_category": report.summary.most_vulnerable_category,
        "severity_distribution": {
            "critical": report.summary.critical_findings,
            "high": report.summary.high_findings,
            "medium": report.summary.medium_findings,
            "low": report.summary.low_findings,
            "info": report.summary.info_findings,
        },
    }

    return analysis


def export_for_jira(report: CampaignReport, output_path: str) -> None:
    """Export findings as a JSON file suitable for Jira ticket creation.

    Each successful finding becomes a separate entry with fields
    that map to common Jira custom fields.
    """
    tickets = []
    for result in report.results:
        if not result.success:
            continue

        # Map severity to Jira priority
        priority_map = {
            Severity.CRITICAL: "Highest",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFO: "Lowest",
        }

        tickets.append({
            "summary": f"[AgentPwn] {result.attack_module}: {result.description[:80]}",
            "description": (
                f"**Attack Module:** {result.attack_module}\n"
                f"**Category:** {result.attack_category}\n"
                f"**Severity:** {result.severity.value.upper()}\n"
                f"**Target:** {report.target.name}\n\n"
                f"**Description:**\n{result.description}\n\n"
                f"**Evidence:**\n{result.evidence.details if result.evidence else 'N/A'}\n\n"
                f"**Payload Used:**\n```\n{result.payload_used[:500]}\n```\n\n"
                f"**Recommendations:**\n"
                + "\n".join(f"- {r}" for r in result.recommendations)
            ),
            "priority": priority_map.get(result.severity, "Medium"),
            "labels": ["security", "agentpwn", result.attack_category],
            "components": ["ai-agent-security"],
        })

    with open(output_path, "w") as f:
        json.dump(tickets, f, indent=2)
    print(f"Exported {len(tickets)} findings to {output_path}")


# ======================================================================
# Main Campaign Workflow
# ======================================================================


async def main() -> None:
    config_path = "campaigns/full_audit.yaml"
    report_dir = "./reports/full_audit"

    # ------------------------------------------------------------------
    # Phase 1: Validate
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Phase 1: Validating campaign configuration")
    print("=" * 60)

    if not validate_campaign(config_path):
        sys.exit(1)

    config = load_campaign_config(config_path)

    # ------------------------------------------------------------------
    # Phase 2: Execute
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Phase 2: Running security audit")
    print("=" * 60)

    engine = CampaignEngine(config, report_dir=report_dir)
    report = await engine.run()

    # Display the results table in the terminal
    engine.display_results_table(report)

    # ------------------------------------------------------------------
    # Phase 3: Analyze
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Phase 3: Post-campaign analysis")
    print("=" * 60)

    analysis = analyze_report(report)

    print(f"\nRisk Score: {analysis['risk_score']:.1f}/100")
    print(f"Success Rate: {analysis['success_rate']:.1f}%")
    print(f"Most Vulnerable Category: {analysis['most_vulnerable_category']}")

    print("\nFindings by Category:")
    for cat, risk in analysis["category_risk"].items():
        print(
            f"  {cat}: {risk['findings_count']} findings "
            f"(max severity: {risk['max_severity']}, "
            f"risk weight: {risk['risk_weight']})"
        )

    print("\nSeverity Distribution:")
    for sev, count in analysis["severity_distribution"].items():
        if count > 0:
            print(f"  {sev.upper()}: {count}")

    # ------------------------------------------------------------------
    # Phase 4: Export
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Phase 4: Exporting results")
    print("=" * 60)

    # Save analysis JSON
    analysis_path = Path(report_dir) / "analysis.json"
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    with open(analysis_path, "w") as f:
        json.dump(analysis, f, indent=2, default=str)
    print(f"Analysis saved to {analysis_path}")

    # Export Jira tickets
    jira_path = Path(report_dir) / "jira_tickets.json"
    export_for_jira(report, str(jira_path))

    # ------------------------------------------------------------------
    # Phase 5: Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Audit Complete")
    print("=" * 60)
    print(f"\nReports directory: {report_dir}/")
    print("Generated files:")
    for path in Path(report_dir).glob("*"):
        print(f"  {path.name} ({path.stat().st_size:,} bytes)")

    # Exit with non-zero code if critical findings were found
    if report.summary.critical_findings > 0:
        print(
            f"\nWARNING: {report.summary.critical_findings} critical "
            f"findings detected. Review immediately."
        )
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())
