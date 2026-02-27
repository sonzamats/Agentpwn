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

"""Generic HTTP target connector for custom agent APIs.

Provides a configurable connector that works with any agent exposed via
an HTTP API. Request format, response parsing, and authentication are
all configurable through the target metadata.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from agentpwn.core.logger import get_logger
from agentpwn.core.models import (
    AgentResponse,
    Message,
    MessageRole,
    TargetConfig,
    ToolCallRecord,
)
from agentpwn.targets.base import BaseTarget

logger = get_logger("target.custom")


class CustomTarget(BaseTarget):
    """Generic HTTP connector for custom agent APIs.

    Configurable via target metadata fields:
    - request_template: JSON template with {message} placeholder
    - response_path: Dot-notation path to extract response text
    - method: HTTP method (default: POST)
    - content_type: Request content type (default: application/json)
    """

    def __init__(self) -> None:
        self._config: TargetConfig | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._messages: list[dict[str, Any]] = []
        self._last_tool_calls: list[ToolCallRecord] = []

    async def initialize(self, config: TargetConfig) -> None:
        """Initialize the custom HTTP connector.

        Args:
            config: Target config with endpoint and metadata settings.
        """
        self._config = config
        self._messages = []

        if not config.endpoint:
            raise RuntimeError("Custom target requires an endpoint URL")

        headers: dict[str, str] = {
            "Content-Type": config.metadata.get("content_type", "application/json"),
        }
        if config.auth and config.auth.api_key:
            headers["Authorization"] = f"Bearer {config.auth.api_key}"
        if config.auth and config.auth.headers:
            headers.update(config.auth.headers)

        self._http_client = httpx.AsyncClient(
            base_url=config.endpoint,
            headers=headers,
            timeout=httpx.Timeout(60.0),
        )

        await logger.ainfo(
            "Custom target initialized",
            endpoint=config.endpoint,
        )

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the custom agent API.

        Args:
            message: The message to send.

        Returns:
            Parsed agent response.
        """
        assert self._http_client is not None
        assert self._config is not None

        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        # Build request from template or default
        template = self._config.metadata.get("request_template")
        method = self._config.metadata.get("method", "POST").upper()
        path = self._config.metadata.get("path", "/")

        if template:
            body = json.loads(json.dumps(template).replace("{message}", message))
        else:
            body = {"message": message}

        try:
            if method == "POST":
                response = await self._http_client.post(path, json=body)
            elif method == "PUT":
                response = await self._http_client.put(path, json=body)
            else:
                response = await self._http_client.get(
                    path, params={"message": message}
                )

            response.raise_for_status()
            data = response.json()

            # Extract response content using configured path
            content = self._extract_response(data)

            return AgentResponse(
                content=content,
                tool_calls=[],
                raw_response=data,
            )
        except httpx.HTTPError as e:
            return AgentResponse(content=f"HTTP error: {e}", tool_calls=[])
        except json.JSONDecodeError:
            return AgentResponse(
                content=response.text if response else "No response",
                tool_calls=[],
            )

    def _extract_response(self, data: Any) -> str:
        """Extract the response text from API response data.

        Uses the configured response_path (dot-notation) or falls back
        to common field names.

        Args:
            data: The parsed JSON response.

        Returns:
            Extracted text content.
        """
        if self._config and self._config.metadata.get("response_path"):
            path = self._config.metadata["response_path"]
            obj: Any = data
            for key in path.split("."):
                if isinstance(obj, dict):
                    obj = obj.get(key, "")
                else:
                    break
            return str(obj)

        # Fallback: try common response field names
        if isinstance(data, dict):
            for key in ["response", "message", "content", "output", "text", "result"]:
                if key in data:
                    return str(data[key])

        return str(data)

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Inject tool output via the custom API.

        Args:
            tool_name: Tool name to simulate.
            output: Crafted tool output.

        Returns:
            Agent response.
        """
        tc = ToolCallRecord(
            tool_name=tool_name,
            arguments={},
            result=output,
            was_injected=True,
        )
        self._last_tool_calls.append(tc)

        # Send as a follow-up message with tool context
        return await self.send_message(
            f"[Tool Output from {tool_name}]\n{output}"
        )

    async def get_tool_calls(self) -> list[ToolCallRecord]:
        """Get tool calls from the last interaction."""
        return self._last_tool_calls

    async def reset(self) -> None:
        """Reset conversation state."""
        self._messages = []
        self._last_tool_calls = []

    async def get_conversation_history(self) -> list[Message]:
        """Get conversation history."""
        return [
            Message(
                role=MessageRole.USER if m["role"] == "user" else MessageRole.ASSISTANT,
                content=m.get("content", ""),
            )
            for m in self._messages
        ]
