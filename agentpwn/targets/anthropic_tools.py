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

"""Anthropic tool-use target connector.

Connects to agents using Anthropic's Messages API with tool use. Handles
the tool_use and tool_result content block protocol, supporting multi-turn
tool interactions and injection testing.
"""

from __future__ import annotations

from typing import Any

import anthropic

from agentpwn.core.logger import get_logger
from agentpwn.core.models import (
    AgentResponse,
    Message,
    MessageRole,
    TargetConfig,
    ToolCallRecord,
)
from agentpwn.targets.base import BaseTarget

logger = get_logger("target.anthropic")


class AnthropicToolsTarget(BaseTarget):
    """Connector for Anthropic tool-use agents.

    Interacts with agents using the Anthropic Messages API with tools.
    Properly handles the tool_use/tool_result content block protocol
    and supports multi-turn tool interactions for security testing.
    """

    def __init__(self) -> None:
        self._client: anthropic.AsyncAnthropic | None = None
        self._config: TargetConfig | None = None
        self._messages: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] = []
        self._system_prompt: str | None = None
        self._last_tool_calls: list[ToolCallRecord] = []

    async def initialize(self, config: TargetConfig) -> None:
        """Set up the Anthropic client.

        Args:
            config: Target configuration with API key and model.
        """
        self._config = config
        api_key = config.auth.api_key if config.auth else None

        client_kwargs: dict[str, Any] = {}
        if api_key:
            client_kwargs["api_key"] = api_key

        self._client = anthropic.AsyncAnthropic(**client_kwargs)
        self._system_prompt = config.system_prompt

        # Convert tool definitions to Anthropic format
        self._tools = [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters or {"type": "object", "properties": {}},
            }
            for tool in config.tools
        ]

        self._messages = []

        await logger.ainfo(
            "Anthropic target initialized",
            model=config.model,
            tools=len(self._tools),
        )

    async def send_message(self, message: str) -> AgentResponse:
        """Send a user message to the Anthropic agent.

        Args:
            message: The user message content.

        Returns:
            The agent's response with any tool_use blocks captured.
        """
        assert self._client is not None
        assert self._config is not None

        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        kwargs: dict[str, Any] = {
            "model": self._config.model or "claude-sonnet-4-20250514",
            "messages": self._messages,
            "max_tokens": 4096,
        }
        if self._system_prompt:
            kwargs["system"] = self._system_prompt
        if self._tools:
            kwargs["tools"] = self._tools

        response = await self._client.messages.create(**kwargs)

        # Parse response content blocks
        text_parts: list[str] = []
        tool_calls: list[ToolCallRecord] = []
        assistant_content: list[dict[str, Any]] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCallRecord(
                        tool_call_id=block.id,
                        tool_name=block.name,
                        arguments=block.input if isinstance(block.input, dict) else {},
                    )
                )
                assistant_content.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )

        self._messages.append({"role": "assistant", "content": assistant_content})
        self._last_tool_calls = tool_calls

        content = "\n".join(text_parts)

        await logger.ainfo(
            "Anthropic response received",
            content_length=len(content),
            tool_calls=len(tool_calls),
            stop_reason=response.stop_reason,
        )

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            raw_response=response.model_dump(),
        )

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Submit a tool result back to the Anthropic agent.

        Finds the pending tool_use block and sends a tool_result content
        block with the crafted output.

        Args:
            tool_name: Name of the tool to respond for.
            output: The tool output content (may contain payloads).

        Returns:
            The agent's subsequent response.
        """
        assert self._client is not None
        assert self._config is not None

        # Find the matching tool call
        tool_use_id = None
        for tc in self._last_tool_calls:
            if tc.tool_name == tool_name:
                tool_use_id = tc.tool_call_id
                tc.result = output
                tc.was_injected = True
                break

        if not tool_use_id:
            tool_use_id = f"injected_{tool_name}"

        # Build tool_result message
        self._messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": output,
                    }
                ],
            }
        )

        kwargs: dict[str, Any] = {
            "model": self._config.model or "claude-sonnet-4-20250514",
            "messages": self._messages,
            "max_tokens": 4096,
        }
        if self._system_prompt:
            kwargs["system"] = self._system_prompt
        if self._tools:
            kwargs["tools"] = self._tools

        response = await self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        new_tool_calls: list[ToolCallRecord] = []
        assistant_content: list[dict[str, Any]] = []

        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
                assistant_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                new_tool_calls.append(
                    ToolCallRecord(
                        tool_call_id=block.id,
                        tool_name=block.name,
                        arguments=block.input if isinstance(block.input, dict) else {},
                    )
                )
                assistant_content.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )

        self._messages.append({"role": "assistant", "content": assistant_content})
        self._last_tool_calls = new_tool_calls

        return AgentResponse(
            content="\n".join(text_parts),
            tool_calls=new_tool_calls,
            raw_response=response.model_dump(),
        )

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
        """Get the current conversation history.

        Returns:
            List of Message objects.
        """
        messages: list[Message] = []
        if self._system_prompt:
            messages.append(Message(role=MessageRole.SYSTEM, content=self._system_prompt))

        for msg in self._messages:
            role_str = msg.get("role", "user")
            role = MessageRole.USER if role_str == "user" else MessageRole.ASSISTANT

            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
                content = "\n".join(text_parts)

            messages.append(Message(role=role, content=content))

        return messages
