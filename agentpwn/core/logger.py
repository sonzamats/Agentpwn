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

"""Structured logging for AgentPwn.

Provides dual-output logging: pretty-printed to console via Rich, and
structured JSON to file for post-hoc analysis. Automatically redacts
sensitive values (API keys, tokens) from all log output.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

import structlog

# Patterns to redact from logs
_SENSITIVE_PATTERNS = [
    re.compile(r"(sk-[a-zA-Z0-9]{20,})"),  # OpenAI keys
    re.compile(r"(sk-ant-[a-zA-Z0-9]{20,})"),  # Anthropic keys
    re.compile(r"(Bearer\s+[a-zA-Z0-9._-]{20,})"),  # Bearer tokens
    re.compile(r"(api[_-]?key[\"']?\s*[:=]\s*[\"']?)([a-zA-Z0-9._-]{16,})"),
]

_REDACTED = "[REDACTED]"


def _redact_sensitive(value: str) -> str:
    """Redact known sensitive patterns from a string.

    Args:
        value: String that may contain sensitive data.

    Returns:
        String with sensitive values replaced by [REDACTED].
    """
    for pattern in _SENSITIVE_PATTERNS:
        value = pattern.sub(_REDACTED, value)
    return value


def _redact_processor(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Structlog processor that redacts sensitive values from log events.

    Args:
        logger: The wrapped logger instance.
        method_name: Name of the log method called.
        event_dict: The event dictionary to process.

    Returns:
        Event dictionary with sensitive values redacted.
    """
    for key, value in event_dict.items():
        if isinstance(value, str):
            event_dict[key] = _redact_sensitive(value)
    return event_dict


def setup_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    json_console: bool = False,
) -> structlog.stdlib.BoundLogger:
    """Configure structured logging for AgentPwn.

    Sets up dual output: pretty console logging via Rich and optional
    JSON file logging for machine analysis.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path for JSON log file output.
        json_console: If True, console output is JSON instead of pretty.

    Returns:
        Configured structlog BoundLogger.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Shared processors
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        _redact_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure standard library logging
    handlers: list[logging.Handler] = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    handlers.append(console_handler)

    # File handler (JSON)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setLevel(logging.DEBUG)  # File always gets everything
        handlers.append(file_handler)

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=handlers,
        force=True,
    )

    # Determine console renderer
    if json_console:
        console_renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        console_renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            pad_event=40,
        )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set formatter on all handlers
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            console_renderer,
        ],
    )
    for handler in handlers:
        handler.setFormatter(formatter)

    # If file handler, give it a JSON formatter
    if log_file and len(handlers) > 1:
        json_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )
        handlers[-1].setFormatter(json_formatter)

    return structlog.get_logger("agentpwn")


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a named logger instance.

    Args:
        name: Logger name. Defaults to 'agentpwn'.

    Returns:
        A structlog BoundLogger.
    """
    return structlog.get_logger(name or "agentpwn")
