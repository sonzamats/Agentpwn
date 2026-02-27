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

"""OpenAI function-calling target connector.

Connects to agents using OpenAI's chat completions API with tool/function
calling. Intercepts tool calls, injects crafted responses, and monitors
the full conversation flow for security analysis.
"""

from __future__ import annotations

import json
from typing import Any

import openai

from agentpwn.core.logger import get_logger
from agentpwn.core.models import (
    AgentResponse,
    Message,
    MessageRole,
    TargetConfig,
    ToolCallRecord,
)
from agentpwn.targets.base import BaseTarget

logger = get_logger("target.openai")


class OpenAIFunctionsTarget(BaseTarget):
    """Connector for OpenAI function-calling agents.

    Interacts with agents using the OpenAI chat completions API with
    tools. Supports intercepting tool calls, injecting tool outputs,
    and monitoring the full conversation for security testing.

    The connector maintains conversation state to enable multi-turn
    attacks and context poisoning tests.
    """

    def __init__(self) -> None:
        self._client: openai.AsyncOpenAI | None = None
        self._config: TargetConfig | None = None
        self._messages: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] = []
        self._last_tool_calls: list[ToolCallRecord] = []

    async def initialize(self, config: TargetConfig) -> None:
        """Set up the OpenAI client with the target configuration.

        Args:
            config: Target configuration including API key and model.
        """
        self._config = config
        api_key = config.auth.api_key if config.auth else None

        client_kwargs: dict[str, Any] = {}
        if api_key:
            client_kwargs["api_key"] = api_key
        if config.endpoint:
            client_kwargs["base_url"] = config.endpoint

        self._client = openai.AsyncOpenAI(**client_kwargs)

        # Convert tool definitions to OpenAI format
        self._tools = [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters or {"type": "object", "properties": {}},
                },
            }
            for tool in config.tools
        ]

        # Initialize with system prompt if provided
        self._messages = []
        if config.system_prompt:
            self._messages.append({"role": "system", "content": config.system_prompt})

        await logger.ainfo(
            "OpenAI target initialized",
            model=config.model,
            tools=len(self._tools),
        )

    async def send_message(self, message: str) -> AgentResponse:
        """Send a user message and get the agent's response.

        Args:
            message: The user message to send.

        Returns:
            The agent's response, including any tool calls it made.
        """
        assert self._client is not None
        assert self._config is not None

        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        kwargs: dict[str, Any] = {
            "model": self._config.model or "gpt-4",
            "messages": self._messages,
        }
        if self._tools:
            kwargs["tools"] = self._tools

        response = await self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        assistant_msg: dict[str, Any] = {"role": "assistant"}

        content = choice.message.content or ""
        if content:
            assistant_msg["content"] = content

        # Process tool calls
        tool_calls: list[ToolCallRecord] = []
        if choice.message.tool_calls:
            assistant_msg["tool_calls"] = []
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {"raw": tc.function.arguments}

                tool_calls.append(
                    ToolCallRecord(
                        tool_call_id=tc.id,
                        tool_name=tc.function.name,
                        arguments=args,
                    )
                )
                assistant_msg["tool_calls"].append(
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                )

        self._messages.append(assistant_msg)
        self._last_tool_calls = tool_calls

        await logger.ainfo(
            "OpenAI response received",
            content_length=len(content),
            tool_calls=len(tool_calls),
        )

        return AgentResponse(
            content=content,
            tool_calls=tool_calls,
            raw_response=response.model_dump(),
        )

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Inject a tool output into the conversation.

        Finds the most recent pending tool call matching the given name
        and submits the crafted output as if it came from that tool.

        Args:
            tool_name: Name of the tool to simulate output for.
            output: The tool output content (may contain attack payloads).

        Returns:
            The agent's response after processing the tool output.
        """
        assert self._client is not None
        assert self._config is not None

        # Find the matching tool call ID
        tool_call_id = None
        for tc in self._last_tool_calls:
            if tc.tool_name == tool_name:
                tool_call_id = tc.tool_call_id
                break

        if not tool_call_id:
            # If no matching call, create a synthetic one
            tool_call_id = f"call_injected_{tool_name}"

        self._messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": output,
            }
        )

        # Mark the tool call as having injected output
        for tc in self._last_tool_calls:
            if tc.tool_call_id == tool_call_id:
                tc.result = output
                tc.was_injected = True

        kwargs: dict[str, Any] = {
            "model": self._config.model or "gpt-4",
            "messages": self._messages,
        }
        if self._tools:
            kwargs["tools"] = self._tools

        response = await self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        content = choice.message.content or ""

        assistant_msg: dict[str, Any] = {"role": "assistant", "content": content}

        # Handle follow-up tool calls
        new_tool_calls: list[ToolCallRecord] = []
        if choice.message.tool_calls:
            assistant_msg["tool_calls"] = []
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {"raw": tc.function.arguments}

                new_tool_calls.append(
                    ToolCallRecord(
                        tool_call_id=tc.id,
                        tool_name=tc.function.name,
                        arguments=args,
                    )
                )
                assistant_msg["tool_calls"].append(
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                )

        self._messages.append(assistant_msg)
        self._last_tool_calls = new_tool_calls

        return AgentResponse(
            content=content,
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
        """Reset the conversation to the initial state."""
        self._messages = []
        if self._config and self._config.system_prompt:
            self._messages.append({"role": "system", "content": self._config.system_prompt})
        self._last_tool_calls = []

    async def get_conversation_history(self) -> list[Message]:
        """Get the current conversation as a list of Message objects.

        Returns:
            Conversation history.
        """
        messages: list[Message] = []
        for msg in self._messages:
            role_map = {
                "system": MessageRole.SYSTEM,
                "user": MessageRole.USER,
                "assistant": MessageRole.ASSISTANT,
                "tool": MessageRole.TOOL,
            }
            role = role_map.get(msg.get("role", "user"), MessageRole.USER)
            content = msg.get("content", "")
            messages.append(
                Message(
                    role=role,
                    content=content or "",
                    tool_call_id=msg.get("tool_call_id"),
                    name=msg.get("name"),
                )
            )
        return messages
