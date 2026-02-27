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

"""Campaign orchestration engine for AgentPwn.

The CampaignEngine is the central coordinator that loads target connectors
and attack modules, runs campaigns, collects results, and produces reports.
It supports both sequential and parallel execution with real-time Rich
terminal output.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import pkgutil
import time
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn
from rich.table import Table

import agentpwn.attacks as attacks_package
from agentpwn.attacks.base import BaseAttack
from agentpwn.core.logger import get_logger
from agentpwn.core.models import (
    AttackConfig,
    AttackResult,
    CampaignConfig,
    CampaignReport,
    ReportFormat,
    Severity,
    TargetType,
)
from agentpwn.core.reporter import ReportGenerator
from agentpwn.targets.base import BaseTarget

logger = get_logger("engine")
console = Console()

# Mapping from TargetType to connector module path
_TARGET_CONNECTORS: dict[TargetType, str] = {
    TargetType.OPENAI_FUNCTIONS: "agentpwn.targets.openai_functions",
    TargetType.ANTHROPIC_TOOLS: "agentpwn.targets.anthropic_tools",
    TargetType.MCP: "agentpwn.targets.mcp_target",
    TargetType.LANGCHAIN: "agentpwn.targets.langchain_target",
    TargetType.CREWAI: "agentpwn.targets.crewai_target",
    TargetType.CUSTOM: "agentpwn.targets.custom_target",
}


class CampaignEngine:
    """Orchestrates security testing campaigns against agentic AI targets.

    The engine dynamically discovers attack modules, loads the appropriate
    target connector, and coordinates attack execution with progress
    reporting and error handling.

    Args:
        config: Campaign configuration defining target and attack parameters.
        report_dir: Directory for output reports.
    """

    def __init__(
        self,
        config: CampaignConfig,
        report_dir: str = "./reports",
    ) -> None:
        self.config = config
        self.report_dir = report_dir
        self.target: BaseTarget | None = None
        self.attack_modules: list[BaseAttack] = []
        self.results: list[AttackResult] = []
        self._reporter = ReportGenerator(output_dir=report_dir)

    async def initialize(self) -> None:
        """Initialize the target connector and discover attack modules.

        Raises:
            RuntimeError: If the target connector cannot be loaded.
        """
        await logger.ainfo(
            "Initializing campaign",
            campaign=self.config.name,
            target=self.config.target.name,
        )

        # Load target connector
        self.target = await self._load_target()
        await self.target.initialize(self.config.target)

        # Discover and load attack modules
        self.attack_modules = self._discover_attacks()

        # Filter to requested modules if specified
        if self.config.attack_modules:
            requested = set(self.config.attack_modules)
            self.attack_modules = [m for m in self.attack_modules if m.name in requested]

        await logger.ainfo(
            "Initialization complete",
            target_type=self.config.target.target_type.value,
            attack_modules=len(self.attack_modules),
        )

    async def run(self) -> CampaignReport:
        """Execute the full campaign and return the report.

        Returns:
            CampaignReport with all results and computed summary.
        """
        if not self.target:
            await self.initialize()

        assert self.target is not None

        report = CampaignReport(
            campaign_name=self.config.name,
            target=self.config.target,
            started_at=datetime.now(timezone.utc),
        )

        total_payloads = sum(len(m.get_payloads()) for m in self.attack_modules)
        await logger.ainfo(
            "Starting campaign",
            modules=len(self.attack_modules),
            total_payloads=total_payloads,
        )

        if self.config.parallel:
            results = await self._run_parallel()
        else:
            results = await self._run_sequential()

        report.results = results
        report.completed_at = datetime.now(timezone.utc)
        report.compute_summary()

        # Generate reports
        report_formats = self.config.report_formats or [ReportFormat.JSON, ReportFormat.MARKDOWN]
        generated_files = await self._reporter.generate(report, report_formats)

        await logger.ainfo(
            "Campaign complete",
            total_attacks=report.total_attacks,
            successful=report.successful_attacks,
            risk_score=report.risk_score,
            reports=[str(f) for f in generated_files],
        )

        return report

    async def _run_sequential(self) -> list[AttackResult]:
        """Run attack modules one at a time with progress display.

        Returns:
            All attack results from all modules.
        """
        all_results: list[AttackResult] = []
        assert self.target is not None

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        )

        with progress:
            task = progress.add_task("Running attacks...", total=len(self.attack_modules))

            for module in self.attack_modules:
                progress.update(task, description=f"Running {module.name}...")

                try:
                    attack_config = AttackConfig(
                        max_attempts=self.config.max_attempts_per_module,
                        timeout_seconds=self.config.timeout_seconds,
                    )
                    results = await asyncio.wait_for(
                        module.execute(self.target, attack_config),
                        timeout=self.config.timeout_seconds,
                    )
                    all_results.extend(results)

                    # Log summary for this module
                    successes = sum(1 for r in results if r.success)
                    await logger.ainfo(
                        "Module complete",
                        module=module.name,
                        payloads=len(results),
                        findings=successes,
                    )

                except asyncio.TimeoutError:
                    await logger.awarning(
                        "Module timed out",
                        module=module.name,
                        timeout=self.config.timeout_seconds,
                    )
                except Exception as e:
                    await logger.aerror(
                        "Module failed",
                        module=module.name,
                        error=str(e),
                    )

                # Reset target state between modules
                try:
                    await self.target.reset()
                except Exception:
                    pass

                progress.advance(task)

        return all_results

    async def _run_parallel(self) -> list[AttackResult]:
        """Run attack modules concurrently.

        Returns:
            All attack results from all modules.
        """
        assert self.target is not None

        async def _run_module(module: BaseAttack) -> list[AttackResult]:
            try:
                attack_config = AttackConfig(
                    max_attempts=self.config.max_attempts_per_module,
                    timeout_seconds=self.config.timeout_seconds,
                )
                return await asyncio.wait_for(
                    module.execute(self.target, attack_config),  # type: ignore[arg-type]
                    timeout=self.config.timeout_seconds,
                )
            except asyncio.TimeoutError:
                await logger.awarning("Module timed out", module=module.name)
                return []
            except Exception as e:
                await logger.aerror("Module failed", module=module.name, error=str(e))
                return []

        tasks = [_run_module(m) for m in self.attack_modules]
        results_lists = await asyncio.gather(*tasks)

        all_results: list[AttackResult] = []
        for results in results_lists:
            all_results.extend(results)
        return all_results

    async def _load_target(self) -> BaseTarget:
        """Dynamically load the appropriate target connector.

        Returns:
            Instantiated target connector.

        Raises:
            RuntimeError: If the connector module cannot be loaded.
        """
        target_type = self.config.target.target_type
        module_path = _TARGET_CONNECTORS.get(target_type)

        if not module_path:
            raise RuntimeError(f"No connector registered for target type: {target_type}")

        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            raise RuntimeError(
                f"Cannot load connector for {target_type.value}. "
                f"You may need to install optional dependencies: {e}"
            ) from e

        # Find the BaseTarget subclass in the module
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseTarget) and obj is not BaseTarget:
                return obj()

        raise RuntimeError(f"No BaseTarget subclass found in {module_path}")

    def _discover_attacks(self) -> list[BaseAttack]:
        """Auto-discover all attack modules in the attacks package.

        Recursively scans the agentpwn.attacks package for classes that
        inherit from BaseAttack and instantiates them.

        Returns:
            List of instantiated attack modules.
        """
        modules: list[BaseAttack] = []

        for importer, modname, ispkg in pkgutil.walk_packages(
            attacks_package.__path__,
            prefix=attacks_package.__name__ + ".",
        ):
            if modname.endswith(".base") or modname.endswith(".__init__"):
                continue
            # Skip payload files
            if ".payloads." in modname:
                continue

            try:
                module = importlib.import_module(modname)
            except ImportError:
                continue

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseAttack)
                    and obj is not BaseAttack
                    and not inspect.isabstract(obj)
                ):
                    try:
                        modules.append(obj())
                    except Exception as e:
                        logger.warning(
                            "Failed to instantiate attack module",
                            module=name,
                            error=str(e),
                        )

        return modules

    def display_results_table(self, report: CampaignReport) -> None:
        """Display a Rich table summarizing campaign results.

        Args:
            report: The completed campaign report.
        """
        table = Table(title="Campaign Results", show_header=True, header_style="bold cyan")
        table.add_column("Module", style="white")
        table.add_column("Payloads", justify="center")
        table.add_column("Findings", justify="center")
        table.add_column("Severity", justify="center")

        # Group results by module
        module_results: dict[str, list[AttackResult]] = {}
        for result in report.results:
            module_results.setdefault(result.attack_module, []).append(result)

        for module_name, results in module_results.items():
            total = len(results)
            findings = sum(1 for r in results if r.success)
            max_severity = _max_severity(results)
            sev_style = _severity_style(max_severity)
            sev_display = f"[{sev_style}]{max_severity.value.upper()}[/{sev_style}]"

            table.add_row(
                module_name,
                f"{total}",
                f"{findings}",
                sev_display if findings > 0 else "[dim]—[/dim]",
            )

        console.print(table)
        console.print()
        console.print(
            f"  Risk Score: [{_severity_style_from_score(report.risk_score)}]"
            f"{report.risk_score:.1f}/100[/]"
        )


def _max_severity(results: list[AttackResult]) -> Severity:
    """Find the highest severity among successful results."""
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in severity_order:
        if any(r.severity == sev and r.success for r in results):
            return sev
    return Severity.INFO


def _severity_style(severity: Severity) -> str:
    """Get Rich style for a severity level."""
    styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return styles.get(severity, "white")


def _severity_style_from_score(score: float) -> str:
    """Get Rich style for a risk score."""
    if score >= 75:
        return "bold red"
    if score >= 50:
        return "bold yellow"
    if score >= 25:
        return "yellow"
    return "green"
