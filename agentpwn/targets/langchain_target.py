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

"""LangChain agent target connector.

Supports two modes of interaction with LangChain agents:
1. **Direct mode**: Import and invoke a LangChain agent directly in-process.
2. **API mode**: Connect to a LangChain agent served via LangServe or
   similar HTTP endpoint.
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

logger = get_logger("target.langchain")


class LangChainTarget(BaseTarget):
    """Connector for LangChain-based agents.

    In API mode, communicates with a LangChain agent via HTTP (e.g.,
    LangServe). In direct mode, invokes the agent programmatically
    using the LangChain Python API.
    """

    def __init__(self) -> None:
        self._config: TargetConfig | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._messages: list[dict[str, Any]] = []
        self._last_tool_calls: list[ToolCallRecord] = []
        self._mode: str = "api"  # "api" or "direct"
        self._agent: Any = None

    async def initialize(self, config: TargetConfig) -> None:
        """Initialize the LangChain connector.

        Args:
            config: Target configuration. Set metadata['langchain_mode']
                to 'direct' for in-process agent access.
        """
        self._config = config
        self._mode = config.metadata.get("langchain_mode", "api")
        self._messages = []
        self._last_tool_calls = []

        if self._mode == "api" and config.endpoint:
            headers: dict[str, str] = {}
            if config.auth and config.auth.api_key:
                headers["Authorization"] = f"Bearer {config.auth.api_key}"
            if config.auth and config.auth.headers:
                headers.update(config.auth.headers)

            self._http_client = httpx.AsyncClient(
                base_url=config.endpoint,
                headers=headers,
                timeout=httpx.Timeout(60.0),
            )
        elif self._mode == "direct":
            # Load the agent from a module path specified in metadata
            agent_path = config.metadata.get("agent_module")
            if agent_path:
                try:
                    import importlib

                    module_path, _, attr_name = agent_path.rpartition(".")
                    module = importlib.import_module(module_path)
                    self._agent = getattr(module, attr_name)
                except (ImportError, AttributeError) as e:
                    raise RuntimeError(
                        f"Cannot load LangChain agent from {agent_path}: {e}"
                    ) from e

        await logger.ainfo(
            "LangChain target initialized",
            mode=self._mode,
            endpoint=config.endpoint,
        )

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the LangChain agent.

        Args:
            message: User message to send.

        Returns:
            The agent's response.
        """
        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        if self._mode == "api":
            return await self._api_send(message)
        else:
            return await self._direct_send(message)

    async def _api_send(self, message: str) -> AgentResponse:
        """Send via HTTP API.

        Args:
            message: The message to send.

        Returns:
            Parsed response.
        """
        assert self._http_client is not None

        # LangServe invoke endpoint
        payload = {
            "input": {"input": message},
            "config": {},
        }

        try:
            response = await self._http_client.post("/invoke", json=payload)
            response.raise_for_status()
            data = response.json()

            output = data.get("output", "")
            if isinstance(output, dict):
                content = output.get("output", str(output))
            else:
                content = str(output)

            # Parse intermediate steps for tool calls
            tool_calls: list[ToolCallRecord] = []
            intermediate = data.get("output", {})
            if isinstance(intermediate, dict):
                for step in intermediate.get("intermediate_steps", []):
                    if isinstance(step, (list, tuple)) and len(step) >= 2:
                        action = step[0]
                        if hasattr(action, "tool"):
                            tool_calls.append(
                                ToolCallRecord(
                                    tool_name=action.tool,
                                    arguments=action.tool_input
                                    if isinstance(action.tool_input, dict)
                                    else {"input": action.tool_input},
                                    result=str(step[1]),
                                )
                            )

            self._last_tool_calls = tool_calls
            return AgentResponse(
                content=content,
                tool_calls=tool_calls,
                raw_response=data,
            )
        except httpx.HTTPError as e:
            await logger.aerror("LangChain API request failed", error=str(e))
            return AgentResponse(content=f"Error: {e}", tool_calls=[])

    async def _direct_send(self, message: str) -> AgentResponse:
        """Invoke the agent directly in-process.

        Args:
            message: The message to send.

        Returns:
            The agent's response.
        """
        if self._agent is None:
            return AgentResponse(
                content="Agent not loaded. Set metadata.agent_module in config.",
                tool_calls=[],
            )

        try:
            # Standard LangChain agent invoke
            import asyncio

            if hasattr(self._agent, "ainvoke"):
                result = await self._agent.ainvoke({"input": message})
            elif hasattr(self._agent, "invoke"):
                result = await asyncio.to_thread(self._agent.invoke, {"input": message})
            else:
                result = await asyncio.to_thread(self._agent.run, message)

            if isinstance(result, dict):
                content = result.get("output", str(result))
            else:
                content = str(result)

            return AgentResponse(content=content, tool_calls=[])
        except Exception as e:
            await logger.aerror("LangChain direct invocation failed", error=str(e))
            return AgentResponse(content=f"Error: {e}", tool_calls=[])

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Inject a tool output for the LangChain agent.

        Args:
            tool_name: Name of the tool.
            output: The crafted tool output.

        Returns:
            The agent's response after processing the output.
        """
        # For LangChain, we inject via a follow-up message that references
        # the tool output, since direct tool output injection requires
        # intercepting the agent's tool execution pipeline.
        injection_message = (
            f"The {tool_name} tool returned the following result:\n\n{output}"
        )

        tc = ToolCallRecord(
            tool_name=tool_name,
            arguments={},
            result=output,
            was_injected=True,
        )
        self._last_tool_calls.append(tc)

        return await self.send_message(injection_message)

    async def get_tool_calls(self) -> list[ToolCallRecord]:
        """Get tool calls from the last interaction.

        Returns:
            List of tool call records.
        """
        return self._last_tool_calls

    async def reset(self) -> None:
        """Reset conversation state."""
        self._messages = []
        self._last_tool_calls = []

    async def get_conversation_history(self) -> list[Message]:
        """Get conversation history.

        Returns:
            List of Message objects.
        """
        return [
            Message(
                role=MessageRole.USER if m["role"] == "user" else MessageRole.ASSISTANT,
                content=m.get("content", ""),
            )
            for m in self._messages
        ]
