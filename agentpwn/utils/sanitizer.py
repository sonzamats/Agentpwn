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

"""Payload sanitization helpers for AgentPwn.

Provides functions to clean, redact, and truncate payloads and agent
responses for safe display in CLI output, logs, and reports.  These are
*display-side* utilities -- they do not modify data sent to targets.

Functions:
    sanitize_for_display: Strip control characters and normalize whitespace.
    redact_secrets: Replace known secret patterns with ``[REDACTED]``.
    truncate_payload: Shorten a payload string to a maximum length.

Usage::

    from agentpwn.utils.sanitizer import sanitize_for_display, redact_secrets

    safe_text = sanitize_for_display(raw_payload)
    redacted = redact_secrets(agent_response)
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from agentpwn.core.logger import get_logger

logger = get_logger("utils.sanitizer")

# ---------------------------------------------------------------------------
# Compiled regex patterns for secret detection
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[a-zA-Z0-9]{20,}")),
    ("Bearer token", re.compile(r"Bearer\s+[a-zA-Z0-9._\-]{20,}")),
    ("Generic API key", re.compile(
        r"(?i)(?:api[_\-]?key|secret|token|password|credential)"
        r"[\"\']?\s*[:=]\s*[\"\']?[a-zA-Z0-9._\-/+]{16,}"
    )),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[ps]_[a-zA-Z0-9]{36}")),
    ("JWT token", re.compile(
        r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+"
    )),
    ("Private key header", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----")),
]

_REDACTED = "[REDACTED]"

# Control characters to strip (C0 and C1 ranges, minus common whitespace).
_CONTROL_CHAR_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)

# Zero-width and invisible Unicode characters.
_INVISIBLE_CHAR_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u034f\u061c"
    r"\u115f\u1160\u17b4\u17b5\u180e\u2000-\u200f"
    r"\u202a-\u202e\u2066-\u2069\ufff9-\ufffb]"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_for_display(
    text: str,
    *,
    max_length: int = 0,
    strip_invisible: bool = True,
    normalize_whitespace: bool = True,
) -> str:
    """Sanitize text for safe display in terminals and reports.

    Removes control characters, optionally strips invisible Unicode
    characters, and normalizes whitespace.  This ensures payloads and
    agent responses render cleanly in CLI output and log files.

    Args:
        text: The raw text to sanitize.
        max_length: If > 0, truncate the result to this many characters
            (appending an ellipsis marker).
        strip_invisible: Whether to remove zero-width and other invisible
            Unicode characters.
        normalize_whitespace: Whether to collapse runs of whitespace into
            single spaces.

    Returns:
        Sanitized text suitable for display.
    """
    if not text:
        return ""

    # Step 1: Remove C0/C1 control characters (keep \n, \r, \t)
    result = _CONTROL_CHAR_RE.sub("", text)

    # Step 2: Optionally strip zero-width / invisible characters
    if strip_invisible:
        result = _INVISIBLE_CHAR_RE.sub("", result)

    # Step 3: Normalize Unicode to NFC form
    result = unicodedata.normalize("NFC", result)

    # Step 4: Optionally normalize whitespace
    if normalize_whitespace:
        # Preserve newlines but collapse other whitespace
        lines = result.split("\n")
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in lines]
        result = "\n".join(lines)

    # Step 5: Truncate if requested
    if max_length > 0 and len(result) > max_length:
        result = result[: max_length - 3] + "..."

    return result


def redact_secrets(
    text: str,
    *,
    replacement: str = _REDACTED,
    additional_patterns: list[re.Pattern[str]] | None = None,
) -> str:
    """Replace known secret patterns in *text* with a redaction marker.

    Scans for API keys, tokens, JWTs, private key headers, and other
    credential-like strings.  Additional custom patterns can be supplied.

    Args:
        text: The text to scan and redact.
        replacement: The string to substitute for detected secrets.
        additional_patterns: Extra compiled regex patterns to match.

    Returns:
        Text with all detected secrets replaced.
    """
    if not text:
        return ""

    result = text
    for name, pattern in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)

    if additional_patterns:
        for pattern in additional_patterns:
            result = pattern.sub(replacement, result)

    return result


def truncate_payload(
    payload: str,
    max_length: int = 500,
    *,
    suffix: str = "... [truncated]",
) -> str:
    """Shorten a payload string to a maximum length.

    Truncates at the nearest word boundary when possible to avoid
    splitting mid-word.

    Args:
        payload: The payload text to truncate.
        max_length: Maximum allowed length in characters.
        suffix: String appended when truncation occurs.

    Returns:
        The truncated payload, or the original if it fits.
    """
    if not payload or len(payload) <= max_length:
        return payload

    # Reserve space for the suffix
    cut_at = max_length - len(suffix)
    if cut_at <= 0:
        return payload[:max_length]

    # Try to cut at a word boundary
    truncated = payload[:cut_at]
    last_space = truncated.rfind(" ")
    if last_space > cut_at * 0.5:
        truncated = truncated[:last_space]

    return truncated + suffix


def sanitize_dict_for_display(
    data: dict[str, Any],
    *,
    redact: bool = True,
    max_value_length: int = 200,
) -> dict[str, Any]:
    """Recursively sanitize a dictionary for display.

    Sanitizes all string values and optionally redacts secrets.  Useful
    for cleaning raw API responses or configuration dicts before logging.

    Args:
        data: The dictionary to sanitize.
        redact: Whether to redact detected secrets in values.
        max_value_length: Maximum length for individual string values.

    Returns:
        A new dictionary with sanitized values.
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            clean = sanitize_for_display(value, max_length=max_value_length)
            if redact:
                clean = redact_secrets(clean)
            sanitized[key] = clean
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict_for_display(
                value, redact=redact, max_value_length=max_value_length
            )
        elif isinstance(value, list):
            sanitized[key] = _sanitize_list(
                value, redact=redact, max_value_length=max_value_length
            )
        else:
            sanitized[key] = value
    return sanitized


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _sanitize_list(
    items: list[Any],
    *,
    redact: bool = True,
    max_value_length: int = 200,
) -> list[Any]:
    """Recursively sanitize a list for display.

    Args:
        items: The list to sanitize.
        redact: Whether to redact secrets.
        max_value_length: Maximum length for string values.

    Returns:
        A new list with sanitized values.
    """
    result: list[Any] = []
    for item in items:
        if isinstance(item, str):
            clean = sanitize_for_display(item, max_length=max_value_length)
            if redact:
                clean = redact_secrets(clean)
            result.append(clean)
        elif isinstance(item, dict):
            result.append(sanitize_dict_for_display(
                item, redact=redact, max_value_length=max_value_length
            ))
        elif isinstance(item, list):
            result.append(_sanitize_list(
                item, redact=redact, max_value_length=max_value_length
            ))
        else:
            result.append(item)
    return result
