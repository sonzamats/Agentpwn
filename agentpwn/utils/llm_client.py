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

"""Unified LLM client supporting OpenAI and Anthropic APIs.

Provides a single :class:`LLMClient` abstraction that can route chat-completion
requests to either the OpenAI or Anthropic API, normalizing the response into
a common :class:`ChatCompletion` format.  This is used internally by AgentPwn
for auxiliary LLM tasks such as payload generation, success evaluation, and
report summarization -- *not* for communicating with the target under test
(that goes through the target connectors).

Usage::

    client = LLMClient(provider="openai", api_key="sk-...", model="gpt-4o")
    result = await client.chat_completion(messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user",   "content": "Summarize this finding."},
    ])
    print(result.content)

Environment variables ``OPENAI_API_KEY`` and ``ANTHROPIC_API_KEY`` are
used as fallbacks when no explicit ``api_key`` is provided.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from agentpwn.core.logger import get_logger

logger = get_logger("utils.llm_client")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class LLMProvider(str, Enum):
    """Supported LLM API providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


@dataclass
class ChatMessage:
    """A single message in a chat conversation.

    Attributes:
        role: The role of the message sender (system, user, assistant).
        content: The text content of the message.
    """

    role: str
    content: str


@dataclass
class ChatCompletion:
    """Normalized response from a chat completion request.

    Attributes:
        content: The assistant's response text.
        model: The model that generated the response.
        usage: Token usage statistics (prompt_tokens, completion_tokens, total_tokens).
        raw_response: The unmodified API response for debugging.
        finish_reason: Why the model stopped generating (stop, length, etc.).
    """

    content: str
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    finish_reason: str = "stop"


# ---------------------------------------------------------------------------
# Client implementation
# ---------------------------------------------------------------------------


class LLMClient:
    """Unified LLM client for OpenAI and Anthropic APIs.

    Handles authentication, request formatting, retry logic, and response
    normalization for both providers.  Uses ``httpx`` for async HTTP to
    avoid pulling in heavy SDK dependencies when only simple completions
    are needed.

    Args:
        provider: Which LLM provider to use.
        api_key: API key for the provider.  Falls back to the standard
            environment variable (``OPENAI_API_KEY`` or ``ANTHROPIC_API_KEY``)
            when not supplied.
        model: Model identifier (e.g. ``gpt-4o``, ``claude-sonnet-4-20250514``).
        base_url: Override the default API base URL.
        max_retries: Number of retries on transient errors.
        timeout: HTTP request timeout in seconds.
        default_max_tokens: Default ``max_tokens`` for completions.

    Raises:
        ValueError: If the provider is not supported or no API key can
            be resolved.
    """

    _OPENAI_BASE = "https://api.openai.com/v1"
    _ANTHROPIC_BASE = "https://api.anthropic.com/v1"

    def __init__(
        self,
        provider: str | LLMProvider = LLMProvider.OPENAI,
        api_key: str | None = None,
        model: str = "gpt-4o",
        base_url: str | None = None,
        max_retries: int = 3,
        timeout: float = 60.0,
        default_max_tokens: int = 1024,
    ) -> None:
        self.provider = LLMProvider(provider)
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
        self.default_max_tokens = default_max_tokens

        # Resolve API key
        self.api_key = api_key or self._resolve_api_key()
        if not self.api_key:
            raise ValueError(
                f"No API key provided for {self.provider.value}. "
                f"Set the appropriate environment variable or pass api_key explicitly."
            )

        # Resolve base URL
        if base_url:
            self.base_url = base_url.rstrip("/")
        elif self.provider == LLMProvider.OPENAI:
            self.base_url = self._OPENAI_BASE
        else:
            self.base_url = self._ANTHROPIC_BASE

        self._client = httpx.AsyncClient(timeout=self.timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def chat_completion(
        self,
        messages: list[dict[str, str] | ChatMessage],
        max_tokens: int | None = None,
        temperature: float = 0.0,
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> ChatCompletion:
        """Send a chat completion request and return the normalized result.

        Args:
            messages: Conversation messages.  Each item must have ``role``
                and ``content`` keys (or be a :class:`ChatMessage`).
            max_tokens: Maximum tokens in the completion.  Falls back to
                :attr:`default_max_tokens`.
            temperature: Sampling temperature (0.0 = deterministic).
            stop: Optional stop sequences.
            **kwargs: Additional provider-specific parameters passed through
                to the API request body.

        Returns:
            A :class:`ChatCompletion` with the assistant's response.

        Raises:
            httpx.HTTPStatusError: On non-retryable HTTP errors.
        """
        normalized = self._normalize_messages(messages)
        effective_max_tokens = max_tokens or self.default_max_tokens

        if self.provider == LLMProvider.OPENAI:
            return await self._openai_completion(
                normalized, effective_max_tokens, temperature, stop, **kwargs
            )
        return await self._anthropic_completion(
            normalized, effective_max_tokens, temperature, stop, **kwargs
        )

    async def close(self) -> None:
        """Close the underlying HTTP client.

        Should be called when the client is no longer needed to release
        connection-pool resources.
        """
        await self._client.aclose()

    async def __aenter__(self) -> LLMClient:
        """Support async context-manager usage."""
        return self

    async def __aexit__(self, *exc: Any) -> None:
        """Close the client on context-manager exit."""
        await self.close()

    # ------------------------------------------------------------------
    # Provider-specific implementations
    # ------------------------------------------------------------------

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _openai_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        stop: list[str] | None,
        **kwargs: Any,
    ) -> ChatCompletion:
        """Execute a chat completion via the OpenAI-compatible API.

        Args:
            messages: Normalized message list.
            max_tokens: Maximum completion tokens.
            temperature: Sampling temperature.
            stop: Optional stop sequences.
            **kwargs: Additional request body parameters.

        Returns:
            Normalized :class:`ChatCompletion`.
        """
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if stop:
            body["stop"] = stop
        body.update(kwargs)

        response = await self._client.post(
            f"{self.base_url}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})

        return ChatCompletion(
            content=choice["message"]["content"] or "",
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            raw_response=data,
            finish_reason=choice.get("finish_reason", "stop"),
        )

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _anthropic_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
        stop: list[str] | None,
        **kwargs: Any,
    ) -> ChatCompletion:
        """Execute a chat completion via the Anthropic Messages API.

        Anthropic uses a different request format: the system message is a
        top-level field rather than part of the messages array.

        Args:
            messages: Normalized message list.
            max_tokens: Maximum completion tokens.
            temperature: Sampling temperature.
            stop: Optional stop sequences.
            **kwargs: Additional request body parameters.

        Returns:
            Normalized :class:`ChatCompletion`.
        """
        # Extract system message (Anthropic wants it as a top-level param)
        system_content: str | None = None
        chat_messages: list[dict[str, str]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                chat_messages.append(msg)

        body: dict[str, Any] = {
            "model": self.model,
            "messages": chat_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_content:
            body["system"] = system_content
        if stop:
            body["stop_sequences"] = stop
        body.update(kwargs)

        response = await self._client.post(
            f"{self.base_url}/messages",
            json=body,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        data = response.json()

        # Anthropic returns content as a list of content blocks
        content_blocks = data.get("content", [])
        text_content = " ".join(
            block.get("text", "") for block in content_blocks if block.get("type") == "text"
        )

        usage = data.get("usage", {})

        return ChatCompletion(
            content=text_content,
            model=data.get("model", self.model),
            usage={
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "total_tokens": (
                    usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                ),
            },
            raw_response=data,
            finish_reason=data.get("stop_reason", "end_turn"),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_api_key(self) -> str:
        """Resolve the API key from standard environment variables.

        Returns:
            The resolved API key, or an empty string if not found.
        """
        if self.provider == LLMProvider.OPENAI:
            return os.environ.get("OPENAI_API_KEY", "")
        return os.environ.get("ANTHROPIC_API_KEY", "")

    @staticmethod
    def _normalize_messages(
        messages: list[dict[str, str] | ChatMessage],
    ) -> list[dict[str, str]]:
        """Normalize messages to plain dictionaries.

        Args:
            messages: Messages that may be dicts or :class:`ChatMessage` objects.

        Returns:
            List of ``{"role": ..., "content": ...}`` dictionaries.
        """
        normalized: list[dict[str, str]] = []
        for msg in messages:
            if isinstance(msg, ChatMessage):
                normalized.append({"role": msg.role, "content": msg.content})
            else:
                normalized.append({"role": msg["role"], "content": msg["content"]})
        return normalized
