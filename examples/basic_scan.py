# Copyright 2026 Wyatt Matson / Matson Capital Group LLC
# Licensed under the Apache License, Version 2.0

"""Basic scan example.

Demonstrates how to load a campaign configuration from a YAML file,
create a CampaignEngine, run the campaign, and display results.

Usage:
    python examples/basic_scan.py campaigns/quick_scan.yaml

Before running, ensure you have:
    1. Set the appropriate API key environment variable (e.g. OPENAI_API_KEY).
    2. Updated the campaign YAML with your target details.
    3. Set permission_confirmed: true after confirming authorization.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from agentpwn.core.config import load_campaign_config
from agentpwn.core.engine import CampaignEngine


async def main(config_path: str) -> None:
    """Load a campaign config and run a basic scan.

    Args:
        config_path: Path to a campaign YAML file.
    """
    # ------------------------------------------------------------------
    # 1. Load the campaign configuration from YAML
    # ------------------------------------------------------------------
    print(f"Loading campaign config from: {config_path}")
    config = load_campaign_config(config_path)

    print(f"Campaign : {config.name}")
    print(f"Target   : {config.target.name} ({config.target.target_type.value})")
    print(f"Modules  : {config.attack_modules or 'all (auto-discover)'}")
    print(f"Parallel : {config.parallel}")
    print()

    # ------------------------------------------------------------------
    # 2. Create the campaign engine
    # ------------------------------------------------------------------
    engine = CampaignEngine(config, report_dir="./reports")

    # ------------------------------------------------------------------
    # 3. Run the campaign
    # ------------------------------------------------------------------
    print("Initializing campaign...")
    await engine.initialize()

    print(f"Loaded {len(engine.attack_modules)} attack module(s). Starting scan...\n")
    report = await engine.run()

    # ------------------------------------------------------------------
    # 4. Display results
    # ------------------------------------------------------------------
    engine.display_results_table(report)

    print(f"\nTotal attacks : {report.total_attacks}")
    print(f"Successful    : {report.successful_attacks}")
    print(f"Risk score    : {report.risk_score:.1f} / 100")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python examples/basic_scan.py <campaign.yaml>")
        print("Example: python examples/basic_scan.py campaigns/quick_scan.yaml")
        sys.exit(1)

    campaign_file = Path(sys.argv[1])
    if not campaign_file.exists():
        print(f"Error: campaign file not found: {campaign_file}")
        sys.exit(1)

    asyncio.run(main(str(campaign_file)))
