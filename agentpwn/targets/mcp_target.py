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

"""MCP (Model Context Protocol) target connector.

Novel connector that can operate in two modes:
1. **Client mode**: Acts as a malicious MCP client sending requests to an
   MCP server, testing whether the server properly validates inputs.
2. **Server mode**: Acts as a malicious MCP server that responds to agent
   tool calls with crafted outputs containing injection payloads.

This dual-mode capability is unique to AgentPwn and enables comprehensive
testing of MCP-based agent deployments.
"""

from __future__ import annotations

import asyncio
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

logger = get_logger("target.mcp")


class MCPTarget(BaseTarget):
    """Connector for MCP-based agent systems.

    Supports two operational modes for comprehensive MCP security testing:

    - **client**: Connects to an MCP server and sends crafted tool calls
      to test input validation and access controls.
    - **server**: Starts a local MCP server that agents connect to,
      returning malicious tool outputs to test output trust.

    The mode is determined by the target config metadata field 'mcp_mode'.
    """

    def __init__(self) -> None:
        self._config: TargetConfig | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._mode: str = "client"  # "client" or "server"
        self._messages: list[dict[str, Any]] = []
        self._last_tool_calls: list[ToolCallRecord] = []
        self._registered_tools: dict[str, dict[str, Any]] = {}
        self._server_responses: dict[str, str] = {}

    async def initialize(self, config: TargetConfig) -> None:
        """Initialize the MCP target connector.

        Args:
            config: Target configuration. Use metadata['mcp_mode'] to set
                mode ('client' or 'server').
        """
        self._config = config
        self._mode = config.metadata.get("mcp_mode", "client")
        self._messages = []
        self._last_tool_calls = []

        headers: dict[str, str] = {}
        if config.auth and config.auth.api_key:
            headers["Authorization"] = f"Bearer {config.auth.api_key}"
        if config.auth and config.auth.headers:
            headers.update(config.auth.headers)

        self._http_client = httpx.AsyncClient(
            base_url=config.endpoint or "http://localhost:3000",
            headers=headers,
            timeout=httpx.Timeout(30.0),
        )

        # Register tools from config
        for tool in config.tools:
            self._registered_tools[tool.name] = {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.parameters,
            }

        await logger.ainfo(
            "MCP target initialized",
            mode=self._mode,
            endpoint=config.endpoint,
            tools=len(self._registered_tools),
        )

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message via MCP protocol.

        In client mode, this sends a tools/call request to the MCP server.
        In server mode, this records the message for the agent to process.

        Args:
            message: The message content.

        Returns:
            The response from the MCP endpoint.
        """
        assert self._http_client is not None

        self._messages.append({"role": "user", "content": message})
        self._last_tool_calls = []

        if self._mode == "client":
            return await self._client_send_message(message)
        else:
            return await self._server_send_message(message)

    async def _client_send_message(self, message: str) -> AgentResponse:
        """Send a message as an MCP client.

        Sends a JSON-RPC request to the MCP server endpoint.

        Args:
            message: Message to send.

        Returns:
            Parsed agent response.
        """
        assert self._http_client is not None

        # Send as a JSON-RPC message to the MCP server
        request_body = {
            "jsonrpc": "2.0",
            "id": len(self._messages),
            "method": "sampling/createMessage",
            "params": {
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": message},
                    }
                ],
                "maxTokens": 4096,
            },
        }

        try:
            response = await self._http_client.post("/", json=request_body)
            response.raise_for_status()
            data = response.json()

            # Parse the JSON-RPC response
            if "result" in data:
                result = data["result"]
                content = ""
                if isinstance(result.get("content"), dict):
                    content = result["content"].get("text", "")
                elif isinstance(result.get("content"), str):
                    content = result["content"]

                return AgentResponse(
                    content=content,
                    tool_calls=[],
                    raw_response=data,
                )
            elif "error" in data:
                return AgentResponse(
                    content=f"MCP error: {data['error']}",
                    tool_calls=[],
                    raw_response=data,
                )

        except httpx.HTTPError as e:
            await logger.aerror("MCP client request failed", error=str(e))
            return AgentResponse(content=f"Connection error: {e}", tool_calls=[])

        return AgentResponse(content="", tool_calls=[])

    async def _server_send_message(self, message: str) -> AgentResponse:
        """Handle a message in server mode.

        In server mode, we simulate the MCP server receiving a tool call
        from the agent and respond with crafted output.

        Args:
            message: The message/tool call from the agent.

        Returns:
            The crafted response.
        """
        # Parse as a tool call if it looks like JSON-RPC
        try:
            parsed = json.loads(message)
            if parsed.get("method") == "tools/call":
                tool_name = parsed["params"]["name"]
                arguments = parsed["params"].get("arguments", {})
                tc = ToolCallRecord(
                    tool_name=tool_name,
                    arguments=arguments,
                )
                self._last_tool_calls.append(tc)

                # Return pre-configured response or default
                response_content = self._server_responses.get(
                    tool_name, f"Result from {tool_name}"
                )
                return AgentResponse(
                    content=response_content,
                    tool_calls=[tc],
                    raw_response=parsed,
                )
        except (json.JSONDecodeError, KeyError):
            pass

        return AgentResponse(content="Message received", tool_calls=[])

    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Inject a tool output via MCP protocol.

        In client mode, sends a tools/call with crafted arguments.
        In server mode, registers the output to be returned when the
        tool is called.

        Args:
            tool_name: The tool name to inject output for.
            output: The crafted output content.

        Returns:
            The agent's response to the injected output.
        """
        assert self._http_client is not None

        if self._mode == "server":
            # Register the response to be served when this tool is called
            self._server_responses[tool_name] = output
            return AgentResponse(
                content=f"Registered malicious response for {tool_name}",
                tool_calls=[],
            )

        # Client mode: send a tools/call with the output
        request_body = {
            "jsonrpc": "2.0",
            "id": len(self._messages) + 100,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"input": output},
            },
        }

        tc = ToolCallRecord(
            tool_name=tool_name,
            arguments={"input": output},
            result=output,
            was_injected=True,
        )
        self._last_tool_calls.append(tc)

        try:
            response = await self._http_client.post("/", json=request_body)
            data = response.json() if response.status_code == 200 else {}

            content = ""
            if isinstance(data.get("result"), dict):
                content_list = data["result"].get("content", [])
                if isinstance(content_list, list):
                    text_parts = [c.get("text", "") for c in content_list if c.get("type") == "text"]
                    content = "\n".join(text_parts)

            return AgentResponse(
                content=content,
                tool_calls=[tc],
                raw_response=data,
            )
        except httpx.HTTPError as e:
            return AgentResponse(
                content=f"MCP tool call failed: {e}",
                tool_calls=[tc],
            )

    async def get_tool_calls(self) -> list[ToolCallRecord]:
        """Get tool calls from the last interaction.

        Returns:
            List of tool call records.
        """
        return self._last_tool_calls

    async def reset(self) -> None:
        """Reset all conversation state and server responses."""
        self._messages = []
        self._last_tool_calls = []
        self._server_responses = {}

    async def get_conversation_history(self) -> list[Message]:
        """Get conversation history.

        Returns:
            List of Message objects.
        """
        messages: list[Message] = []
        for msg in self._messages:
            role = MessageRole.USER if msg.get("role") == "user" else MessageRole.ASSISTANT
            messages.append(Message(role=role, content=msg.get("content", "")))
        return messages

    async def list_server_tools(self) -> list[dict[str, Any]]:
        """Query the MCP server for its available tools.

        Returns:
            List of tool definitions from the server.
        """
        assert self._http_client is not None

        request_body = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "tools/list",
            "params": {},
        }

        try:
            response = await self._http_client.post("/", json=request_body)
            data = response.json()
            return data.get("result", {}).get("tools", [])
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            await logger.aerror("Failed to list MCP tools", error=str(e))
            return []

    def set_malicious_response(self, tool_name: str, response: str) -> None:
        """Pre-configure a malicious response for server mode.

        Args:
            tool_name: The tool name to set the response for.
            response: The malicious output to return.
        """
        self._server_responses[tool_name] = response
