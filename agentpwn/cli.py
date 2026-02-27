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

"""Click-based CLI for AgentPwn.

Provides the ``agentpwn`` command-line entry point with subcommands for
running campaigns, listing modules, generating config templates, and
validating configuration files.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import agentpwn
from agentpwn.core.config import (
    ConfigError,
    create_template_config,
    load_campaign_config,
    validate_config,
)
from agentpwn.core.engine import CampaignEngine
from agentpwn.core.logger import setup_logging

console = Console()

_BANNER = r"""
     _                    _   ____
    / \   __ _  ___ _ __ | |_|  _ \__      ___ __
   / _ \ / _` |/ _ \ '_ \| __| |_) \ \ /\ / / '_ \
  / ___ \ (_| |  __/ | | | |_|  __/ \ V  V /| | | |
 /_/   \_\__, |\___|_| |_|\__|_|     \_/\_/ |_| |_|
         |___/
"""


@click.group()
@click.version_option(version=agentpwn.__version__, prog_name="agentpwn")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose (DEBUG) logging.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all non-error output.")
@click.option("--json-logs", is_flag=True, help="Emit structured JSON logs to stderr.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, json_logs: bool) -> None:
    """AgentPwn — Security testing framework for agentic AI systems."""
    ctx.ensure_object(dict)
    level = "DEBUG" if verbose else ("ERROR" if quiet else "INFO")
    setup_logging(level=level, json_console=json_logs)
    ctx.obj["quiet"] = quiet


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option(
    "--report-dir", "-o", default="./reports", help="Directory for output reports."
)
@click.option(
    "--format",
    "-f",
    "report_formats",
    multiple=True,
    type=click.Choice(["json", "markdown", "html"]),
    help="Report format(s). Can be specified multiple times.",
)
@click.option(
    "--module",
    "-m",
    "modules",
    multiple=True,
    help="Run only specific module(s). Can be specified multiple times.",
)
@click.option("--parallel", "-p", is_flag=True, help="Run modules in parallel.")
@click.pass_context
def run(
    ctx: click.Context,
    config_path: str,
    report_dir: str,
    report_formats: tuple[str, ...],
    modules: tuple[str, ...],
    parallel: bool,
) -> None:
    """Run a security testing campaign.

    CONFIG_PATH is the path to a campaign YAML configuration file.
    """
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        console.print(Panel(_BANNER, title="AgentPwn", subtitle=f"v{agentpwn.__version__}"))

    try:
        config = load_campaign_config(config_path)
    except ConfigError as e:
        console.print(f"[bold red]Configuration error:[/] {e}")
        raise SystemExit(1)

    # Apply CLI overrides
    if report_formats:
        from agentpwn.core.models import ReportFormat

        config.report_formats = [ReportFormat(f) for f in report_formats]

    if modules:
        config.attack_modules = list(modules)

    if parallel:
        config.parallel = True

    if not config.permission_confirmed:
        console.print(
            "[bold yellow]WARNING:[/] You must confirm you have authorization to test "
            "this target by setting [bold]permission_confirmed: true[/] in your config."
        )
        raise SystemExit(1)

    if not quiet:
        console.print(f"  Campaign : [bold]{config.name}[/]")
        console.print(
            f"  Target   : [bold]{config.target.name}[/] "
            f"({config.target.target_type.value} / {config.target.model or 'N/A'})"
        )
        console.print()

    engine = CampaignEngine(config, report_dir=report_dir)

    try:
        report = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Campaign interrupted by user.[/]")
        raise SystemExit(130)
    except Exception as e:
        console.print(f"[bold red]Campaign failed:[/] {e}")
        raise SystemExit(1)

    if not quiet:
        engine.display_results_table(report)
        console.print()
        console.print(
            f"  [bold green]Reports written to:[/] {report_dir}/"
        )


@main.command()
@click.argument("output_path", default="campaign.yaml")
def init(output_path: str) -> None:
    """Generate a template campaign configuration file.

    OUTPUT_PATH is where to write the template (default: campaign.yaml).
    """
    path = create_template_config(output_path)
    console.print(f"[bold green]Template written to:[/] {path}")
    console.print("Edit the file to configure your target and run:")
    console.print(f"  [bold]agentpwn run {path}[/]")


@main.command(name="validate")
@click.argument("config_path", type=click.Path(exists=True))
def validate_cmd(config_path: str) -> None:
    """Validate a campaign configuration file.

    CONFIG_PATH is the path to the YAML file to validate.
    """
    errors = validate_config(config_path)
    if errors:
        console.print(f"[bold red]Validation failed ({len(errors)} error(s)):[/]")
        for err in errors:
            console.print(f"  - {err}")
        raise SystemExit(1)
    else:
        console.print("[bold green]Configuration is valid.[/]")


@main.command(name="list-modules")
def list_modules() -> None:
    """List all available attack modules."""
    from agentpwn.attacks.base import BaseAttack
    from agentpwn.core.engine import CampaignEngine

    # Use engine's discovery mechanism
    engine = CampaignEngine.__new__(CampaignEngine)
    modules = engine._discover_attacks()

    table = Table(
        title="Available Attack Modules",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Module", style="white")
    table.add_column("Category", style="dim")
    table.add_column("Severity", justify="center")
    table.add_column("Description", max_width=50)

    severity_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for module in sorted(modules, key=lambda m: (m.category, m.name)):
        sev = module.severity.value
        style = severity_styles.get(sev, "white")
        table.add_row(
            module.name,
            module.category,
            f"[{style}]{sev.upper()}[/{style}]",
            module.description[:80],
        )

    console.print(table)
    console.print(f"\n  [bold]{len(modules)}[/] modules available.")


@main.command(name="list-targets")
def list_targets() -> None:
    """List all supported target types."""
    from agentpwn.core.models import TargetType

    table = Table(
        title="Supported Target Types",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Type", style="white")
    table.add_column("Description")

    descriptions = {
        TargetType.OPENAI_FUNCTIONS: "OpenAI function calling / tool use API",
        TargetType.ANTHROPIC_TOOLS: "Anthropic tool use API",
        TargetType.MCP: "Model Context Protocol (MCP) servers",
        TargetType.LANGCHAIN: "LangChain agents and chains",
        TargetType.CREWAI: "CrewAI multi-agent crews",
        TargetType.CUSTOM: "Custom agent via HTTP or BaseTarget subclass",
    }

    for target_type in TargetType:
        table.add_row(target_type.value, descriptions.get(target_type, ""))

    console.print(table)


if __name__ == "__main__":
    main()
