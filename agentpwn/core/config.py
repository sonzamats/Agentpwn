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

"""Configuration management for AgentPwn.

Loads campaign and user configuration from YAML files, with support for
environment variable overrides (especially for API keys). Validates all
configuration against Pydantic models before use.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentpwn.core.models import CampaignConfig, TargetConfig


# Default locations for user config
_USER_CONFIG_PATHS = [
    Path.home() / ".agentpwn.yaml",
    Path.home() / ".agentpwn.yml",
    Path.home() / ".config" / "agentpwn" / "config.yaml",
]

# Environment variable prefix for overrides
_ENV_PREFIX = "AGENTPWN_"


class ConfigError(Exception):
    """Raised when configuration is invalid or cannot be loaded."""


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load and parse a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        ConfigError: If the file cannot be read or parsed.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(data, dict):
        raise ConfigError(f"Expected a YAML mapping in {path}, got {type(data).__name__}")
    return data


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variable overrides to configuration.

    Environment variables prefixed with AGENTPWN_ override nested config
    keys using double-underscore separators. For example:
        AGENTPWN_TARGET__API_KEY=sk-xxx  ->  data["target"]["api_key"] = "sk-xxx"

    API keys are always resolved from environment variables for security.

    Args:
        data: Configuration dictionary to modify.

    Returns:
        The modified configuration dictionary.
    """
    # Direct API key resolution from well-known env vars
    if "target" in data and isinstance(data["target"], dict):
        target = data["target"]
        if "auth" not in target or target["auth"] is None:
            target["auth"] = {}
        auth = target["auth"]

        # Auto-resolve API keys from standard environment variables
        if not auth.get("api_key"):
            target_type = target.get("target_type", "")
            if target_type in ("openai_functions",):
                auth["api_key"] = os.environ.get("OPENAI_API_KEY", "")
            elif target_type in ("anthropic_tools",):
                auth["api_key"] = os.environ.get("ANTHROPIC_API_KEY", "")

    # Generic AGENTPWN_ prefix overrides
    for key, value in os.environ.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        config_path = key[len(_ENV_PREFIX) :].lower().split("__")
        _set_nested(data, config_path, value)

    return data


def _set_nested(data: dict[str, Any], keys: list[str], value: str) -> None:
    """Set a nested dictionary value using a list of keys.

    Args:
        data: Dictionary to modify.
        keys: Path of keys into the dictionary.
        value: Value to set.
    """
    for key in keys[:-1]:
        if key not in data or not isinstance(data[key], dict):
            data[key] = {}
        data = data[key]
    data[keys[-1]] = value


def load_campaign_config(path: str | Path) -> CampaignConfig:
    """Load and validate a campaign configuration file.

    Args:
        path: Path to the campaign YAML file.

    Returns:
        Validated CampaignConfig instance.

    Raises:
        ConfigError: If the file is invalid or fails validation.
    """
    data = load_yaml(path)
    data = _apply_env_overrides(data)

    try:
        return CampaignConfig(**data)
    except ValidationError as e:
        raise ConfigError(f"Invalid campaign configuration: {e}") from e


def load_user_config() -> dict[str, Any]:
    """Load the user's global AgentPwn configuration.

    Searches standard paths for a user config file. Returns an empty
    dict if no user config is found.

    Returns:
        User configuration dictionary.
    """
    for config_path in _USER_CONFIG_PATHS:
        if config_path.exists():
            return load_yaml(config_path)
    return {}


def create_template_config(output_path: str | Path) -> Path:
    """Generate a template campaign configuration file.

    Args:
        output_path: Where to write the template.

    Returns:
        Path to the created file.
    """
    template = {
        "name": "my-campaign",
        "description": "Security audit of my agent",
        "target": {
            "name": "my-agent",
            "target_type": "openai_functions",
            "model": "gpt-4",
            "endpoint": "https://api.openai.com/v1",
            "tools": [
                {
                    "name": "web_search",
                    "description": "Search the web",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                    "permissions": ["network"],
                    "risk_level": "medium",
                }
            ],
            "auth": {"api_key": "${OPENAI_API_KEY}"},
        },
        "attack_modules": [],
        "max_attempts_per_module": 10,
        "timeout_seconds": 300,
        "parallel": False,
        "report_formats": ["json", "markdown"],
        "permission_confirmed": False,
    }

    output_path = Path(output_path)
    with open(output_path, "w") as f:
        yaml.dump(template, f, default_flow_style=False, sort_keys=False)
    return output_path


def validate_config(path: str | Path) -> list[str]:
    """Validate a campaign configuration file and return any errors.

    Args:
        path: Path to the campaign YAML file.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: list[str] = []
    try:
        data = load_yaml(path)
    except ConfigError as e:
        return [str(e)]

    try:
        config = CampaignConfig(**data)
    except ValidationError as e:
        for error in e.errors():
            loc = " -> ".join(str(l) for l in error["loc"])
            errors.append(f"{loc}: {error['msg']}")
        return errors

    # Additional semantic validation
    if not config.permission_confirmed:
        errors.append(
            "permission_confirmed must be true. You must confirm you have "
            "authorization to test this target."
        )

    if config.target.target_type != "custom" and not config.target.model:
        errors.append("target.model is required for non-custom target types")

    return errors


def resolve_target_config(data: dict[str, Any]) -> TargetConfig:
    """Build a TargetConfig from a raw dictionary with env var resolution.

    Args:
        data: Raw target configuration dictionary.

    Returns:
        Validated TargetConfig instance.

    Raises:
        ConfigError: If validation fails.
    """
    # Resolve ${ENV_VAR} references in string values
    resolved = _resolve_env_vars(data)
    try:
        return TargetConfig(**resolved)
    except ValidationError as e:
        raise ConfigError(f"Invalid target configuration: {e}") from e


def _resolve_env_vars(data: Any) -> Any:
    """Recursively resolve ${ENV_VAR} references in configuration values.

    Args:
        data: Configuration data (may be dict, list, or scalar).

    Returns:
        Data with environment variable references resolved.
    """
    if isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        env_var = data[2:-1]
        return os.environ.get(env_var, "")
    elif isinstance(data, dict):
        return {k: _resolve_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_resolve_env_vars(item) for item in data]
    return data
