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

"""Token counting utilities for AgentPwn.

Provides fast, dependency-light token estimation for payloads and messages.
When the optional ``tiktoken`` library is available it is used for accurate
counts; otherwise a heuristic estimator is used.

These utilities help ensure payloads stay within model context limits and
allow cost estimation before sending requests.

Usage::

    from agentpwn.utils.tokenizer import estimate_tokens, estimate_cost

    count = estimate_tokens("Hello, world!", model="gpt-4o")
    cost = estimate_cost(prompt_tokens=500, completion_tokens=200, model="gpt-4o")
"""

from __future__ import annotations

import math
import re
from typing import Any

from agentpwn.core.logger import get_logger

logger = get_logger("utils.tokenizer")

# ---------------------------------------------------------------------------
# Optional tiktoken import
# ---------------------------------------------------------------------------

_tiktoken_available: bool = False
_tiktoken_cache: dict[str, Any] = {}

try:
    import tiktoken as _tiktoken  # type: ignore[import-untyped]

    _tiktoken_available = True
except ImportError:
    _tiktoken = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Model context-window sizes and pricing (per 1M tokens, in USD)
# ---------------------------------------------------------------------------

_MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
    "claude-opus-4-20250514": 200_000,
    "claude-sonnet-4-20250514": 200_000,
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "claude-3-opus-20240229": 200_000,
}

_MODEL_PRICING: dict[str, dict[str, float]] = {
    # Prices per 1M tokens: {"prompt": $X, "completion": $Y}
    "gpt-4o": {"prompt": 2.50, "completion": 10.00},
    "gpt-4o-mini": {"prompt": 0.15, "completion": 0.60},
    "gpt-4-turbo": {"prompt": 10.00, "completion": 30.00},
    "gpt-4": {"prompt": 30.00, "completion": 60.00},
    "gpt-3.5-turbo": {"prompt": 0.50, "completion": 1.50},
    "claude-opus-4-20250514": {"prompt": 15.00, "completion": 75.00},
    "claude-sonnet-4-20250514": {"prompt": 3.00, "completion": 15.00},
    "claude-3-5-sonnet-20241022": {"prompt": 3.00, "completion": 15.00},
    "claude-3-5-haiku-20241022": {"prompt": 0.80, "completion": 4.00},
}

# Average characters per token for heuristic estimation.
# English text averages ~4 chars/token; code is closer to ~3.5.
_CHARS_PER_TOKEN_TEXT: float = 4.0
_CHARS_PER_TOKEN_CODE: float = 3.5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def estimate_tokens(
    text: str,
    model: str = "gpt-4o",
) -> int:
    """Estimate the number of tokens in *text* for the given *model*.

    Uses ``tiktoken`` for accurate counts when available and the model
    is supported, otherwise falls back to a character-based heuristic.

    Args:
        text: The text to tokenize.
        model: Model identifier used to select the tokenizer encoding.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0

    # Try tiktoken first
    if _tiktoken_available:
        encoding = _get_tiktoken_encoding(model)
        if encoding is not None:
            return len(encoding.encode(text))

    # Heuristic fallback
    return _heuristic_token_count(text)


def estimate_messages_tokens(
    messages: list[dict[str, str]],
    model: str = "gpt-4o",
) -> int:
    """Estimate total tokens for a list of chat messages.

    Accounts for per-message overhead tokens used by the OpenAI chat
    format (role tags, separators, etc.).

    Args:
        messages: List of ``{"role": ..., "content": ...}`` dicts.
        model: Model identifier for tokenizer selection.

    Returns:
        Estimated total token count including message overhead.
    """
    # OpenAI chat format: each message has ~4 overhead tokens
    # (role, name, content delimiters, separator).
    overhead_per_message = 4
    # Every reply is primed with 3 tokens for the assistant turn.
    reply_priming = 3

    total = reply_priming
    for message in messages:
        total += overhead_per_message
        total += estimate_tokens(message.get("content", ""), model=model)
        total += estimate_tokens(message.get("role", ""), model=model)
        if "name" in message:
            total += estimate_tokens(message["name"], model=model)
            total += 1  # name field adds one extra token
    return total


def get_context_window(model: str) -> int:
    """Return the context-window size for the given model.

    Args:
        model: Model identifier.

    Returns:
        Maximum context length in tokens.  Defaults to 8192 for unknown
        models.
    """
    return _MODEL_CONTEXT_WINDOWS.get(model, 8_192)


def estimate_cost(
    prompt_tokens: int,
    completion_tokens: int,
    model: str = "gpt-4o",
) -> float:
    """Estimate the USD cost for a completion request.

    Args:
        prompt_tokens: Number of prompt / input tokens.
        completion_tokens: Number of completion / output tokens.
        model: Model identifier for pricing lookup.

    Returns:
        Estimated cost in USD.  Returns ``0.0`` for unknown models.
    """
    pricing = _MODEL_PRICING.get(model)
    if not pricing:
        return 0.0

    prompt_cost = (prompt_tokens / 1_000_000) * pricing["prompt"]
    completion_cost = (completion_tokens / 1_000_000) * pricing["completion"]
    return prompt_cost + completion_cost


def fits_in_context(
    text: str,
    model: str = "gpt-4o",
    reserved_for_completion: int = 1024,
) -> bool:
    """Check whether *text* fits within the model's context window.

    Args:
        text: The text to check.
        model: Model identifier.
        reserved_for_completion: Tokens to reserve for the model's reply.

    Returns:
        ``True`` if the text fits, ``False`` otherwise.
    """
    token_count = estimate_tokens(text, model=model)
    window = get_context_window(model)
    return token_count <= (window - reserved_for_completion)


def truncate_to_token_limit(
    text: str,
    max_tokens: int,
    model: str = "gpt-4o",
) -> str:
    """Truncate *text* to fit within *max_tokens*.

    If ``tiktoken`` is available, truncation is token-exact.  Otherwise
    it uses the heuristic character ratio.

    Args:
        text: The text to truncate.
        max_tokens: Maximum allowed tokens.
        model: Model identifier for tokenizer selection.

    Returns:
        Truncated text that fits within the token limit.
    """
    if estimate_tokens(text, model=model) <= max_tokens:
        return text

    if _tiktoken_available:
        encoding = _get_tiktoken_encoding(model)
        if encoding is not None:
            tokens = encoding.encode(text)
            return encoding.decode(tokens[:max_tokens])

    # Heuristic truncation
    chars_per_token = _detect_chars_per_token(text)
    max_chars = int(max_tokens * chars_per_token)
    return text[:max_chars]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_tiktoken_encoding(model: str) -> Any:
    """Get (or cache) the tiktoken encoding for a model.

    Args:
        model: Model identifier.

    Returns:
        A tiktoken Encoding object, or ``None`` if the model is not
        supported by tiktoken.
    """
    if model in _tiktoken_cache:
        return _tiktoken_cache[model]

    try:
        encoding = _tiktoken.encoding_for_model(model)
        _tiktoken_cache[model] = encoding
        return encoding
    except KeyError:
        # Model not known to tiktoken -- try cl100k_base as fallback
        try:
            encoding = _tiktoken.get_encoding("cl100k_base")
            _tiktoken_cache[model] = encoding
            return encoding
        except Exception:
            _tiktoken_cache[model] = None
            return None


def _heuristic_token_count(text: str) -> int:
    """Estimate token count using character and word heuristics.

    Uses a hybrid approach: character ratio for the base estimate,
    with adjustments for whitespace density and special characters.

    Args:
        text: The text to estimate.

    Returns:
        Estimated token count.
    """
    chars_per_token = _detect_chars_per_token(text)
    base_estimate = len(text) / chars_per_token

    # Adjust for whitespace-heavy text (more tokens per char)
    whitespace_ratio = len(re.findall(r"\s", text)) / max(len(text), 1)
    if whitespace_ratio > 0.3:
        base_estimate *= 1.1

    return max(1, math.ceil(base_estimate))


def _detect_chars_per_token(text: str) -> float:
    """Detect whether text is primarily code or natural language.

    Code typically has a lower chars-per-token ratio due to operators,
    brackets, and short identifiers.

    Args:
        text: The text to analyze.

    Returns:
        Estimated characters per token.
    """
    # Simple heuristic: if the text has many code-like characters, treat as code
    code_chars = set("{}[]();=<>|&!@#$%^*~`")
    code_char_count = sum(1 for c in text if c in code_chars)
    code_ratio = code_char_count / max(len(text), 1)

    if code_ratio > 0.05:
        return _CHARS_PER_TOKEN_CODE
    return _CHARS_PER_TOKEN_TEXT
