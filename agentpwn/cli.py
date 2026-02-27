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

Provides the ``agentpwn`` command-line interface with Rich terminal output.
The CLI is the primary entry point for running security campaigns, executing
individual attack modules, and generating reports.

Commands:
    scan            Run a campaign from a YAML config or a quick scan.
    attack          Run a single attack module against a target.
    list-attacks    List all available attack modules.
    list-targets    List all supported target connector types.
    report          Regenerate a report from a saved campaign JSON.
    init            Generate a template campaign configuration file.
    validate        Validate a campaign configuration file.

Entry point (registered in pyproject.toml)::

    [project.scripts]
    agentpwn = "agentpwn.cli:main"
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import pkgutil
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

import agentpwn
import agentpwn.attacks as attacks_package
from agentpwn.attacks.base import BaseAttack
from agentpwn.core.config import (
    ConfigError,
    create_template_config,
    load_campaign_config,
    validate_config,
)
from agentpwn.core.engine import CampaignEngine
from agentpwn.core.logger import setup_logging
from agentpwn.core.models import (
    AttackConfig,
    CampaignConfig,
    CampaignReport,
    ReportFormat,
    Severity,
    TargetConfig,
    TargetType,
)
from agentpwn.core.reporter import ReportGenerator

# ---------------------------------------------------------------------------
# Rich console and theming
# ---------------------------------------------------------------------------

_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "severity.critical": "bold red",
    "severity.high": "bold yellow",
    "severity.medium": "yellow",
    "severity.low": "blue",
    "severity.info": "dim",
})

console = Console(theme=_THEME)

# ---------------------------------------------------------------------------
# ASCII art banner
# ---------------------------------------------------------------------------

_BANNER = r"""
    ___                    __  ____
   /   | ____ ____  ____  / /_/ __ \      ______
  / /| |/ __ `/ _ \/ __ \/ __/ /_/ | /| / / __ \
 / ___ / /_/ /  __/ / / / /_/ ____/ / |/ / / / /
/_/  |_\__, /\___/_/ /_/\__/_/    |__/|__/_/ /_/
      /____/
"""

_TAGLINE = "Security Testing Framework for Agentic AI Systems"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    """Print the AgentPwn ASCII art banner."""
    banner_text = Text(_BANNER, style="bold red")
    console.print(banner_text)
    console.print(f"  [bold cyan]{_TAGLINE}[/bold cyan]")
    console.print(
        f"  [dim]v{agentpwn.__version__} -- "
        f"https://github.com/sonzamats/Agentpwn[/dim]"
    )
    console.print()


def _severity_style(severity: str) -> str:
    """Return the Rich style string for a severity label.

    Args:
        severity: The severity string (critical, high, medium, low, info).

    Returns:
        Rich markup style string.
    """
    styles: dict[str, str] = {
        "critical": "severity.critical",
        "high": "severity.high",
        "medium": "severity.medium",
        "low": "severity.low",
        "info": "severity.info",
    }
    return styles.get(severity.lower(), "white")


def _discover_attack_modules() -> list[BaseAttack]:
    """Auto-discover all attack modules in the attacks package.

    Recursively scans the ``agentpwn.attacks`` package for concrete
    subclasses of :class:`BaseAttack` and instantiates them.

    Returns:
        List of instantiated attack module instances.
    """
    modules: list[BaseAttack] = []
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        attacks_package.__path__,
        prefix=attacks_package.__name__ + ".",
    ):
        if modname.endswith(".base") or modname.endswith(".__init__"):
            continue
        if ".payloads." in modname:
            continue

        try:
            module = importlib.import_module(modname)
        except ImportError:
            continue

        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseAttack)
                and obj is not BaseAttack
                and not inspect.isabstract(obj)
            ):
                try:
                    modules.append(obj())
                except Exception:
                    pass

    return modules


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from synchronous Click context.

    Uses ``asyncio.run()`` when no event loop is running, otherwise
    falls back to a thread-pool executor.

    Args:
        coro: The coroutine to execute.

    Returns:
        The coroutine's return value.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Click CLI group and commands
# ---------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@click.version_option(version=agentpwn.__version__, prog_name="agentpwn")
@click.option(
    "--verbose", "-v", is_flag=True, default=False, help="Enable verbose (DEBUG) logging."
)
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress non-error output.")
@click.option(
    "--json-logs", is_flag=True, default=False, help="Emit structured JSON logs to stderr."
)
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, json_logs: bool) -> None:
    """AgentPwn -- Security testing framework for agentic AI systems."""
    ctx.ensure_object(dict)
    level = "DEBUG" if verbose else ("ERROR" if quiet else "INFO")
    setup_logging(level=level, json_console=json_logs)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print(ctx.get_help())


# ---- scan ----------------------------------------------------------------


@main.command()
@click.argument("config_path", type=click.Path(exists=True), required=False)
@click.option(
    "--target-type",
    "-t",
    type=click.Choice([t.value for t in TargetType]),
    help="Target type for quick scan (no config file).",
)
@click.option("--model", "-m", help="Model identifier for quick scan.")
@click.option("--endpoint", "-e", help="API endpoint for quick scan.")
@click.option(
    "--report-dir",
    "-o",
    default="./reports",
    show_default=True,
    help="Directory for output reports.",
)
@click.option(
    "--format",
    "-f",
    "report_formats",
    multiple=True,
    type=click.Choice(["json", "html", "markdown"]),
    default=["json", "markdown"],
    show_default=True,
    help="Report output formats.",
)
@click.option(
    "--module",
    "modules",
    multiple=True,
    help="Run only specific module(s). Can be specified multiple times.",
)
@click.option(
    "--parallel/--sequential",
    default=False,
    show_default=True,
    help="Run attack modules in parallel.",
)
@click.option(
    "--max-attempts",
    default=10,
    show_default=True,
    help="Maximum payload attempts per module.",
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Confirm authorization to test the target.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    config_path: str | None,
    target_type: str | None,
    model: str | None,
    endpoint: str | None,
    report_dir: str,
    report_formats: tuple[str, ...],
    modules: tuple[str, ...],
    parallel: bool,
    max_attempts: int,
    confirm: bool,
) -> None:
    """Run a security campaign from a config file or quick scan.

    If CONFIG_PATH is provided, the campaign is loaded from the YAML file.
    Otherwise, use --target-type, --model, and --endpoint for a quick scan.

    Examples::

        agentpwn scan campaign.yaml

        agentpwn scan -t openai_functions -m gpt-4o --confirm
    """
    quiet: bool = ctx.obj.get("quiet", False)

    if not quiet:
        _print_banner()

    if config_path:
        # Load from YAML config
        try:
            campaign_config = load_campaign_config(config_path)
        except ConfigError as e:
            console.print(f"[error]Configuration error:[/error] {e}")
            raise SystemExit(1) from e

        # Apply CLI overrides
        if report_formats:
            campaign_config.report_formats = [ReportFormat(f) for f in report_formats]
        if modules:
            campaign_config.attack_modules = list(modules)
        if parallel:
            campaign_config.parallel = True

    elif target_type:
        # Quick scan mode
        if not confirm:
            console.print(
                "[error]You must pass --confirm to acknowledge you have "
                "authorization to test this target.[/error]"
            )
            raise SystemExit(1)

        target_config = TargetConfig(
            name=f"quick-scan-{target_type}",
            target_type=TargetType(target_type),
            model=model,
            endpoint=endpoint,
        )
        campaign_config = CampaignConfig(
            name="quick-scan",
            description="Quick scan initiated from CLI",
            target=target_config,
            attack_modules=list(modules) if modules else [],
            max_attempts_per_module=max_attempts,
            parallel=parallel,
            report_formats=[ReportFormat(f) for f in report_formats],
            permission_confirmed=True,
        )
    else:
        console.print(
            "[warning]Provide a config file path or use --target-type "
            "for a quick scan.[/warning]"
        )
        console.print(ctx.get_help())
        raise SystemExit(1)

    if not campaign_config.permission_confirmed:
        console.print(
            Panel(
                "[error]Permission not confirmed.[/error]\n\n"
                "You must set [bold]permission_confirmed: true[/bold] in your "
                "campaign config to acknowledge that you have authorization "
                "to test this target.",
                title="Authorization Required",
                border_style="red",
            )
        )
        raise SystemExit(1)

    if not quiet:
        console.print(
            Panel(
                f"[bold]Campaign:[/bold] {campaign_config.name}\n"
                f"[bold]Target:[/bold]   {campaign_config.target.name} "
                f"({campaign_config.target.target_type.value})\n"
                f"[bold]Model:[/bold]    {campaign_config.target.model or 'N/A'}",
                title="Campaign Configuration",
                border_style="cyan",
            )
        )
        console.print()

    engine = CampaignEngine(config=campaign_config, report_dir=report_dir)

    try:
        report: CampaignReport = _run_async(engine.run())
    except KeyboardInterrupt:
        console.print("\n[warning]Campaign interrupted by user.[/warning]")
        raise SystemExit(130)
    except Exception as e:
        console.print(f"[error]Campaign failed:[/error] {e}")
        raise SystemExit(1) from e

    if not quiet:
        _display_campaign_results(report)
        console.print(f"\n  [success]Reports written to:[/success] {report_dir}/")


# ---- attack --------------------------------------------------------------


@main.command()
@click.argument("module_name")
@click.option(
    "--target-type",
    "-t",
    required=True,
    type=click.Choice([t.value for t in TargetType]),
    help="Target agent framework type.",
)
@click.option("--model", "-m", help="Model identifier.")
@click.option("--endpoint", "-e", help="API endpoint URL.")
@click.option(
    "--max-attempts", default=10, show_default=True, help="Max payload attempts."
)
@click.option(
    "--timeout", default=60, show_default=True, help="Timeout per attempt (seconds)."
)
@click.option(
    "--confirm",
    is_flag=True,
    default=False,
    help="Confirm authorization to test the target.",
)
@click.pass_context
def attack(
    ctx: click.Context,
    module_name: str,
    target_type: str,
    model: str | None,
    endpoint: str | None,
    max_attempts: int,
    timeout: int,
    confirm: bool,
) -> None:
    """Run a single attack module against a target.

    MODULE_NAME is the attack module identifier (e.g. tool_output_injection).
    Use 'agentpwn list-attacks' to see available modules.

    Examples::

        agentpwn attack tool_output_injection -t openai_functions -m gpt-4o --confirm
    """
    quiet: bool = ctx.obj.get("quiet", False)

    if not quiet:
        _print_banner()

    if not confirm:
        console.print(
            "[error]You must pass --confirm to acknowledge you have "
            "authorization to test this target.[/error]"
        )
        raise SystemExit(1)

    # Find the requested module
    all_modules = _discover_attack_modules()
    matched = [m for m in all_modules if m.name == module_name]

    if not matched:
        console.print(f"[error]Attack module '{module_name}' not found.[/error]")
        console.print("[info]Available modules:[/info]")
        for m in sorted(all_modules, key=lambda x: x.name):
            console.print(f"  - {m.name}")
        raise SystemExit(1)

    attack_module = matched[0]

    if not quiet:
        console.print(
            Panel(
                f"[bold]Module:[/bold]      {attack_module.name}\n"
                f"[bold]Category:[/bold]    {attack_module.category}\n"
                f"[bold]Description:[/bold] {attack_module.description}\n"
                f"[bold]Target:[/bold]      {target_type} / {model or 'default'}",
                title="Attack Configuration",
                border_style="cyan",
            )
        )
        console.print()

    target_config = TargetConfig(
        name=f"single-attack-{target_type}",
        target_type=TargetType(target_type),
        model=model,
        endpoint=endpoint,
    )
    campaign_config = CampaignConfig(
        name=f"attack-{module_name}",
        description=f"Single attack: {module_name}",
        target=target_config,
        attack_modules=[module_name],
        max_attempts_per_module=max_attempts,
        timeout_seconds=timeout,
        permission_confirmed=True,
    )

    engine = CampaignEngine(config=campaign_config)

    try:
        report: CampaignReport = _run_async(engine.run())
    except KeyboardInterrupt:
        console.print("\n[warning]Attack interrupted by user.[/warning]")
        raise SystemExit(130)
    except Exception as e:
        console.print(f"[error]Attack failed:[/error] {e}")
        raise SystemExit(1) from e

    if not quiet:
        _display_campaign_results(report)


# ---- list-attacks --------------------------------------------------------


@main.command("list-attacks")
@click.option("--category", "-c", help="Filter by attack category.")
@click.option("--verbose", "-v", is_flag=True, help="Show full descriptions and MITRE IDs.")
def list_attacks(category: str | None, verbose: bool) -> None:
    """List all available attack modules.

    Examples::

        agentpwn list-attacks

        agentpwn list-attacks --category prompt_injection -v
    """
    _print_banner()

    modules = _discover_attack_modules()
    if category:
        modules = [m for m in modules if m.category == category]

    if not modules:
        console.print("[warning]No attack modules found.[/warning]")
        if category:
            console.print(f"[dim]Filter: category={category}[/dim]")
        return

    table = Table(
        title="Available Attack Modules",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Module", style="bold white", min_width=30)
    table.add_column("Category", style="cyan")
    table.add_column("Severity", justify="center")
    if verbose:
        table.add_column("Description", max_width=50)
        table.add_column("MITRE", style="dim")

    for module in sorted(modules, key=lambda m: (m.category, m.name)):
        sev_style = _severity_style(module.severity.value)
        severity_display = f"[{sev_style}]{module.severity.value.upper()}[/{sev_style}]"

        row: list[str] = [module.name, module.category, severity_display]
        if verbose:
            row.append(module.description[:80])
            row.append(module.mitre_mapping or "N/A")
        table.add_row(*row)

    console.print(table)
    console.print(f"\n  [dim]Total: {len(modules)} module(s)[/dim]")


# ---- list-targets --------------------------------------------------------


@main.command("list-targets")
def list_targets() -> None:
    """List all supported target connector types.

    Shows the agent frameworks AgentPwn can test, along with their
    connector module paths and required dependencies.
    """
    _print_banner()

    table = Table(
        title="Supported Target Types",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Target Type", style="bold white", min_width=20)
    table.add_column("Connector Module", style="dim")
    table.add_column("Extra Dependencies", style="cyan")
    table.add_column("Description")

    _targets: list[tuple[str, str, str, str]] = [
        (
            "openai_functions",
            "agentpwn.targets.openai_functions",
            "openai",
            "OpenAI function calling / tool use API",
        ),
        (
            "anthropic_tools",
            "agentpwn.targets.anthropic_tools",
            "anthropic",
            "Anthropic tool use API",
        ),
        (
            "mcp",
            "agentpwn.targets.mcp_target",
            "mcp",
            "Model Context Protocol (MCP) servers",
        ),
        (
            "langchain",
            "agentpwn.targets.langchain_target",
            "langchain, langchain-core",
            "LangChain agents and chains",
        ),
        (
            "crewai",
            "agentpwn.targets.crewai_target",
            "crewai",
            "CrewAI multi-agent crews",
        ),
        (
            "custom",
            "agentpwn.targets.custom_target",
            "none",
            "Custom agent via HTTP or BaseTarget subclass",
        ),
    ]

    for target_type, module_path, deps, description in _targets:
        table.add_row(target_type, module_path, deps, description)

    console.print(table)
    console.print(
        "\n  [dim]Install optional deps with: "
        "pip install agentpwn[langchain] or pip install agentpwn[all][/dim]"
    )


# ---- report --------------------------------------------------------------


@main.command()
@click.argument("json_path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "report_formats",
    multiple=True,
    type=click.Choice(["json", "html", "markdown"]),
    default=["json", "markdown", "html"],
    show_default=True,
    help="Report output formats.",
)
@click.option(
    "--output-dir",
    "-o",
    default="./reports",
    show_default=True,
    help="Directory for output reports.",
)
def report(
    json_path: str,
    report_formats: tuple[str, ...],
    output_dir: str,
) -> None:
    """Regenerate a report from a saved campaign JSON file.

    JSON_PATH is the path to a previously saved campaign report in JSON
    format.

    Examples::

        agentpwn report reports/abc123.json --format html

        agentpwn report results.json -f markdown -f html -o ./output
    """
    _print_banner()

    try:
        with open(json_path) as f:
            data = json.load(f)
        campaign_report = CampaignReport(**data)
    except Exception as e:
        console.print(f"[error]Failed to load report:[/error] {e}")
        raise SystemExit(1) from e

    formats = [ReportFormat(f) for f in report_formats]
    generator = ReportGenerator(output_dir=output_dir)

    try:
        generated_files = _run_async(generator.generate(campaign_report, formats))
    except Exception as e:
        console.print(f"[error]Report generation failed:[/error] {e}")
        raise SystemExit(1) from e

    console.print("[success]Reports generated successfully:[/success]")
    for path in generated_files:
        console.print(f"  [dim]{path}[/dim]")

    _display_campaign_results(campaign_report)


# ---- init ----------------------------------------------------------------


@main.command()
@click.option(
    "--output",
    "-o",
    default="agentpwn-campaign.yaml",
    show_default=True,
    help="Output path for the template.",
)
def init(output: str) -> None:
    """Generate a template campaign configuration file.

    Creates a YAML file with example values that you can customize for
    your target agent.

    Examples::

        agentpwn init

        agentpwn init -o my-campaign.yaml
    """
    _print_banner()

    output_path = Path(output)
    if output_path.exists():
        if not click.confirm(f"File '{output}' already exists. Overwrite?"):
            console.print("[dim]Aborted.[/dim]")
            return

    try:
        created = create_template_config(output_path)
        console.print(f"[success]Template config created:[/success] {created}")
        console.print(
            "\n[dim]Edit the file to match your target agent, then run:[/dim]"
        )
        console.print(f"  [bold]agentpwn scan {created}[/bold]")
    except Exception as e:
        console.print(f"[error]Failed to create template:[/error] {e}")
        raise SystemExit(1) from e


# ---- validate ------------------------------------------------------------


@main.command()
@click.argument("config_path", type=click.Path(exists=True))
def validate(config_path: str) -> None:
    """Validate a campaign configuration file.

    Checks the YAML syntax, Pydantic model validation, and semantic rules
    (e.g., permission_confirmed must be true).

    Examples::

        agentpwn validate campaign.yaml
    """
    _print_banner()

    errors = validate_config(config_path)

    if not errors:
        console.print(
            Panel(
                "[success]Configuration is valid.[/success]\n\n"
                f"File: {config_path}",
                title="Validation Passed",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[error]Found {len(errors)} validation error(s):[/error]",
                title="Validation Failed",
                border_style="red",
            )
        )
        for i, error in enumerate(errors, 1):
            console.print(f"  [error]{i}.[/error] {error}")

        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _display_campaign_results(report: CampaignReport) -> None:
    """Display a Rich-formatted summary of campaign results.

    Produces a table of per-module results and a summary panel with the
    overall risk score, finding counts, and a visual risk bar.

    Args:
        report: The completed campaign report.
    """
    console.print()

    # Results table
    table = Table(
        title="Campaign Results",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Module", style="white", min_width=25)
    table.add_column("Category", style="cyan")
    table.add_column("Payloads", justify="center")
    table.add_column("Findings", justify="center")
    table.add_column("Severity", justify="center")

    # Group results by module
    module_results: dict[str, list[Any]] = {}
    for result in report.results:
        module_results.setdefault(result.attack_module, []).append(result)

    for module_name, results in sorted(module_results.items()):
        total = len(results)
        findings = sum(1 for r in results if r.success)
        result_category = results[0].attack_category if results else "unknown"

        # Find highest severity among successful results
        severities = [r.severity for r in results if r.success]
        if severities:
            severity_order = [
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO,
            ]
            max_sev = Severity.INFO
            for sev in severity_order:
                if sev in severities:
                    max_sev = sev
                    break
            sev_style = _severity_style(max_sev.value)
            sev_display = f"[{sev_style}]{max_sev.value.upper()}[/{sev_style}]"
        else:
            sev_display = "[dim]---[/dim]"

        findings_display = (
            f"[bold red]{findings}[/bold red]" if findings > 0
            else f"[success]{findings}[/success]"
        )

        table.add_row(
            module_name, result_category, str(total), findings_display, sev_display,
        )

    console.print(table)
    console.print()

    # Summary panel
    score = report.risk_score
    if score >= 75:
        score_style = "bold red"
        risk_label = "CRITICAL RISK"
    elif score >= 50:
        score_style = "bold yellow"
        risk_label = "HIGH RISK"
    elif score >= 25:
        score_style = "yellow"
        risk_label = "MEDIUM RISK"
    elif score >= 5:
        score_style = "green"
        risk_label = "LOW RISK"
    else:
        score_style = "bold green"
        risk_label = "MINIMAL RISK"

    # Build visual risk bar
    filled = int(score / 5)
    empty = 20 - filled
    risk_bar = (
        f"[{score_style}]{'█' * filled}[/{score_style}]"
        f"[dim]{'░' * empty}[/dim]"
    )

    summary = report.summary
    summary_text = (
        f"[bold]Risk Score:[/bold] "
        f"[{score_style}]{score:.1f}/100 -- {risk_label}[/{score_style}]\n"
        f"  {risk_bar}\n\n"
        f"[bold]Total Attacks:[/bold] {report.total_attacks}\n"
        f"[bold]Successful:[/bold]   {report.successful_attacks}\n"
        f"[bold]Modules Run:[/bold]  {summary.total_modules_run}\n\n"
        f"[severity.critical]Critical: {summary.critical_findings}[/severity.critical]  "
        f"[severity.high]High: {summary.high_findings}[/severity.high]  "
        f"[severity.medium]Medium: {summary.medium_findings}[/severity.medium]  "
        f"[severity.low]Low: {summary.low_findings}[/severity.low]  "
        f"[severity.info]Info: {summary.info_findings}[/severity.info]"
    )

    console.print(
        Panel(
            summary_text,
            title="Campaign Summary",
            border_style=score_style,
        )
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    main()
