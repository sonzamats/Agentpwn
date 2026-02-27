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

"""Report generation for AgentPwn campaigns.

Produces campaign reports in JSON, Markdown, and self-contained HTML formats.
Reports include executive summaries, detailed findings, and risk score
visualizations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agentpwn.core.models import CampaignReport, ReportFormat, Severity


class ReportGenerator:
    """Generates campaign reports in multiple formats.

    Args:
        output_dir: Directory where reports will be written.
    """

    def __init__(self, output_dir: str | Path = "./reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(
        self,
        report: CampaignReport,
        formats: list[ReportFormat] | None = None,
    ) -> list[Path]:
        """Generate reports in the specified formats.

        Args:
            report: The campaign report data.
            formats: List of formats to generate. Defaults to JSON + Markdown.

        Returns:
            List of paths to generated report files.
        """
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.MARKDOWN]

        generated: list[Path] = []
        for fmt in formats:
            if fmt == ReportFormat.JSON:
                generated.append(self._generate_json(report))
            elif fmt == ReportFormat.MARKDOWN:
                generated.append(self._generate_markdown(report))
            elif fmt == ReportFormat.HTML:
                generated.append(self._generate_html(report))
        return generated

    def _generate_json(self, report: CampaignReport) -> Path:
        """Generate a JSON report.

        Args:
            report: The campaign report data.

        Returns:
            Path to the generated JSON file.
        """
        path = self.output_dir / f"{report.campaign_id}.json"
        with open(path, "w") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
        return path

    def _generate_markdown(self, report: CampaignReport) -> Path:
        """Generate a GitHub-compatible Markdown report.

        Args:
            report: The campaign report data.

        Returns:
            Path to the generated Markdown file.
        """
        path = self.output_dir / f"{report.campaign_id}.md"

        lines: list[str] = []
        lines.append(f"# AgentPwn Campaign Report: {report.campaign_name}")
        lines.append("")
        lines.append(f"**Campaign ID:** `{report.campaign_id}`  ")
        lines.append(f"**Target:** {report.target.name} ({report.target.target_type.value})  ")
        lines.append(f"**Model:** {report.target.model or 'N/A'}  ")
        lines.append(f"**Started:** {_format_dt(report.started_at)}  ")
        lines.append(f"**Completed:** {_format_dt(report.completed_at)}  ")
        lines.append("")

        # Risk Score
        lines.append("## Risk Score")
        lines.append("")
        score = report.risk_score
        risk_label = _risk_label(score)
        lines.append(f"**{score:.1f} / 100** — {risk_label}")
        lines.append("")
        lines.append(_risk_bar(score))
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        s = report.summary
        lines.append(f"- **Total attacks executed:** {report.total_attacks}")
        lines.append(f"- **Successful attacks:** {report.successful_attacks}")
        lines.append(f"- **Modules run:** {s.total_modules_run}")
        lines.append(f"- **Critical findings:** {s.critical_findings}")
        lines.append(f"- **High findings:** {s.high_findings}")
        lines.append(f"- **Medium findings:** {s.medium_findings}")
        lines.append(f"- **Low findings:** {s.low_findings}")
        lines.append(f"- **Most vulnerable category:** {s.most_vulnerable_category}")
        lines.append("")

        # Detailed Findings
        lines.append("## Detailed Findings")
        lines.append("")

        successful_results = [r for r in report.results if r.success]
        if not successful_results:
            lines.append("No successful attacks were recorded.")
        else:
            for i, result in enumerate(successful_results, 1):
                sev_badge = _severity_badge(result.severity)
                lines.append(f"### {i}. {result.attack_module} {sev_badge}")
                lines.append("")
                lines.append(f"**Category:** {result.attack_category}  ")
                lines.append(f"**Severity:** {result.severity.value.upper()}  ")
                lines.append(f"**Timestamp:** {_format_dt(result.timestamp)}  ")
                lines.append("")
                lines.append(f"**Description:** {result.description}")
                lines.append("")

                if result.evidence:
                    lines.append(f"**Evidence Type:** {result.evidence.type.value}  ")
                    lines.append(f"**Details:** {result.evidence.details}")
                    lines.append("")

                if result.payload_used:
                    lines.append("**Payload:**")
                    lines.append("```")
                    lines.append(result.payload_used[:500])
                    lines.append("```")
                    lines.append("")

                if result.recommendations:
                    lines.append("**Recommendations:**")
                    for rec in result.recommendations:
                        lines.append(f"- {rec}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # All results table
        lines.append("## All Attack Results")
        lines.append("")
        lines.append("| Module | Category | Success | Severity |")
        lines.append("|--------|----------|---------|----------|")
        for result in report.results:
            status = "PASS" if result.success else "FAIL"
            lines.append(
                f"| {result.attack_module} | {result.attack_category} "
                f"| {status} | {result.severity.value} |"
            )
        lines.append("")

        # Footer
        lines.append("---")
        lines.append(
            f"*Generated by AgentPwn v0.1.0 at {_format_dt(datetime.now(timezone.utc))}*"
        )

        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    def _generate_html(self, report: CampaignReport) -> Path:
        """Generate a self-contained HTML report with embedded CSS.

        Args:
            report: The campaign report data.

        Returns:
            Path to the generated HTML file.
        """
        path = self.output_dir / f"{report.campaign_id}.html"
        s = report.summary
        score = report.risk_score
        risk_label = _risk_label(score)
        score_color = _score_color(score)

        findings_rows = ""
        for result in report.results:
            if result.success:
                sev_class = result.severity.value
                findings_rows += f"""
                <tr class="finding-{sev_class}">
                    <td>{result.attack_module}</td>
                    <td>{result.attack_category}</td>
                    <td><span class="severity {sev_class}">{result.severity.value.upper()}</span></td>
                    <td>{result.description[:200]}</td>
                    <td>{'; '.join(result.recommendations[:2]) if result.recommendations else 'N/A'}</td>
                </tr>"""

        all_rows = ""
        for result in report.results:
            status_class = "success" if result.success else "fail"
            all_rows += f"""
            <tr>
                <td>{result.attack_module}</td>
                <td>{result.attack_category}</td>
                <td><span class="status {status_class}">{'PASS' if result.success else 'FAIL'}</span></td>
                <td><span class="severity {result.severity.value}">{result.severity.value.upper()}</span></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentPwn Report: {report.campaign_name}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
           background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
    h2 {{ color: #8b949e; margin: 2rem 0 1rem; border-bottom: 1px solid #21262d; padding-bottom: 0.5rem; }}
    .meta {{ color: #8b949e; margin-bottom: 2rem; }}
    .meta span {{ display: inline-block; margin-right: 2rem; }}
    .score-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                  padding: 2rem; text-align: center; margin: 1rem 0; }}
    .score-number {{ font-size: 3rem; font-weight: bold; color: {score_color}; }}
    .score-label {{ font-size: 1.2rem; color: #8b949e; }}
    .score-bar {{ height: 8px; background: #21262d; border-radius: 4px; margin-top: 1rem; }}
    .score-fill {{ height: 100%; border-radius: 4px; background: {score_color};
                   width: {score}%; transition: width 0.5s; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
              gap: 1rem; margin: 1rem 0; }}
    .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1rem; text-align: center; }}
    .stat-value {{ font-size: 2rem; font-weight: bold; }}
    .stat-label {{ color: #8b949e; font-size: 0.85rem; }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
    th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }}
    th {{ color: #8b949e; font-weight: 600; }}
    .severity {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
    .severity.critical {{ background: #da3633; color: white; }}
    .severity.high {{ background: #d29922; color: white; }}
    .severity.medium {{ background: #e3b341; color: #0d1117; }}
    .severity.low {{ background: #3fb950; color: #0d1117; }}
    .severity.info {{ background: #388bfd; color: white; }}
    .status {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }}
    .status.success {{ background: #da3633; color: white; }}
    .status.fail {{ background: #3fb950; color: #0d1117; }}
    .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #21262d;
               color: #484f58; text-align: center; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>AgentPwn Campaign Report</h1>
    <div class="meta">
        <span>Campaign: <strong>{report.campaign_name}</strong></span>
        <span>Target: <strong>{report.target.name}</strong></span>
        <span>Model: <strong>{report.target.model or 'N/A'}</strong></span>
    </div>

    <h2>Risk Score</h2>
    <div class="score-box">
        <div class="score-number">{score:.1f}</div>
        <div class="score-label">{risk_label}</div>
        <div class="score-bar"><div class="score-fill"></div></div>
    </div>

    <h2>Summary</h2>
    <div class="stats">
        <div class="stat"><div class="stat-value">{report.total_attacks}</div><div class="stat-label">Total Attacks</div></div>
        <div class="stat"><div class="stat-value" style="color: #da3633;">{report.successful_attacks}</div><div class="stat-label">Successful</div></div>
        <div class="stat"><div class="stat-value">{s.critical_findings}</div><div class="stat-label">Critical</div></div>
        <div class="stat"><div class="stat-value">{s.high_findings}</div><div class="stat-label">High</div></div>
        <div class="stat"><div class="stat-value">{s.medium_findings}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-value">{s.low_findings}</div><div class="stat-label">Low</div></div>
    </div>

    <h2>Findings</h2>
    <table>
        <thead><tr><th>Module</th><th>Category</th><th>Severity</th><th>Description</th><th>Recommendations</th></tr></thead>
        <tbody>{findings_rows if findings_rows else '<tr><td colspan="5" style="text-align:center;color:#484f58;">No successful attacks recorded</td></tr>'}</tbody>
    </table>

    <h2>All Attack Results</h2>
    <table>
        <thead><tr><th>Module</th><th>Category</th><th>Result</th><th>Severity</th></tr></thead>
        <tbody>{all_rows}</tbody>
    </table>

    <div class="footer">
        Generated by AgentPwn v0.1.0 &mdash; {_format_dt(datetime.now(timezone.utc))}
    </div>
</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
        return path


def _format_dt(dt: datetime | None) -> str:
    """Format a datetime for display."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _risk_label(score: float) -> str:
    """Convert a numeric risk score to a human label."""
    if score >= 75:
        return "CRITICAL RISK"
    if score >= 50:
        return "HIGH RISK"
    if score >= 25:
        return "MEDIUM RISK"
    if score >= 5:
        return "LOW RISK"
    return "MINIMAL RISK"


def _risk_bar(score: float) -> str:
    """Generate a text-based risk bar for Markdown."""
    filled = int(score / 5)
    empty = 20 - filled
    return f"`[{'█' * filled}{'░' * empty}] {score:.1f}/100`"


def _severity_badge(severity: Severity) -> str:
    """Generate a severity badge for Markdown."""
    return f"[{severity.value.upper()}]"


def _score_color(score: float) -> str:
    """Return a CSS color for a risk score."""
    if score >= 75:
        return "#da3633"
    if score >= 50:
        return "#d29922"
    if score >= 25:
        return "#e3b341"
    return "#3fb950"
