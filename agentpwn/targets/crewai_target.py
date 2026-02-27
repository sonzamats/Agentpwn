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

"""CrewAI agent target connector.

Connects to CrewAI multi-agent systems for security testing. Supports
both API-based and programmatic access to test inter-agent communication
trust boundaries and tool delegation patterns.
"""

from __future__ import annotations

import asyncio
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

logger = get_logger("target.crewai")


class CrewAITarget(BaseTarget):
    """Connector for CrewAI multi-agent systems.

    Tests security of CrewAI agent crews by sending crafted inputs
    and monitoring tool delegation and inter-agent communication
    patterns for potential exploitation paths.
    """

    def __init__(self) -> None:
        self._config: TargetConfig | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._messages: list[dict[str, Any]] = []
        self._last_tool_calls: list[ToolCallRecord] = []
        self._crew: Any = None

    async def initialize(self, config: TargetConfig) -> None:
        """Initialize the CrewAI connector.

        Args:
            config: Target config. Use metadata['crew_module'] for direct access.
        """
        self._config = config
        self._messages = []
        self._last_tool_calls = []

        if config.endpoint:
            headers: dict[str, str] = {}
            if config.auth and config.auth.api_key:
                headers["Authorization"] = f"Bearer {config.auth.api_key}"
            if config.auth and config.auth.headers:
                headers.update(config.auth.headers)

            self._http_client = httpx.AsyncClient(
                base_url=config.endpoint,
                headers=headers,
                timeout=httpx.Timeout(120.0),  # CrewAI tasks can be slow
            )
        else:
            # Direct mode: load crew from module
            crew_path = config.metadata.get("crew_module")
            if crew_path:
                try:
                    import importlib

                    module_path, _, attr_name = crew_path.rpartition(".")
                    module = importlib.import_module(module_path)
                    self._crew = getattr(module, attr_name)
                except (ImportError, AttributeError) as e:
                    raise RuntimeError(
                        f"Cannot load CrewAI crew from {crew_path}: {e}"
                    ) from e

        await logger.ainfo("CrewAI target initialized", endpoint=config.endpoint)

    async def send_message(self, message: str) -> AgentResponse:
        """Send a task to the CrewAI system.

        Args:
            message: The task/message to process.

        Returns:
            The crew's response.
        """
        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        if self._http_client:
            return await self._api_send(message)
        elif self._crew:
            return await self._direct_send(message)
        return AgentResponse(content="No CrewAI target configured", tool_calls=[])

    async def _api_send(self, message: str) -> AgentResponse:
        """Send via HTTP API.

        Args:
            message: The message to send.

        Returns:
            Parsed response.
        """
        assert self._http_client is not None

        try:
            response = await self._http_client.post(
                "/kickoff",
                json={"inputs": {"task": message}},
            )
            response.raise_for_status()
            data = response.json()

            content = data.get("result", str(data))
            return AgentResponse(content=content, tool_calls=[], raw_response=data)
        except httpx.HTTPError as e:
            return AgentResponse(content=f"CrewAI API error: {e}", tool_calls=[])

    async def _direct_send(self, message: str) -> AgentResponse:
        """Invoke CrewAI crew directly.

        Args:
            message: The task to execute.

        Returns:
            The crew's result.
        """
        try:
            if hasattr(self._crew, "kickoff"):
                result = await asyncio.to_thread(
                    self._crew.kickoff, inputs={"task": message}
                )
            else:
                result = await asyncio.to_thread(self._crew, message)

            content = str(result)
            return AgentResponse(content=content, tool_calls=[])
        except Exception as e:
            return AgentResponse(content=f"CrewAI error: {e}", tool_calls=[])

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Inject a tool output into the CrewAI conversation.

        Args:
            tool_name: Tool name to simulate.
            output: Crafted tool output.

        Returns:
            The agent's response.
        """
        tc = ToolCallRecord(
            tool_name=tool_name,
            arguments={},
            result=output,
            was_injected=True,
        )
        self._last_tool_calls.append(tc)

        injection = f"Tool {tool_name} returned: {output}"
        return await self.send_message(injection)

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
