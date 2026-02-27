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

"""Abstract base class for target agent connectors.

All target connectors implement this interface to provide a uniform way
for attack modules to interact with different agent frameworks. The
interface covers the full lifecycle: initialization, message sending,
tool output injection, state inspection, and cleanup.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from agentpwn.core.models import AgentResponse, Message, TargetConfig, ToolCallRecord


class BaseTarget(ABC):
    """Abstract base class for all target agent connectors.

    Subclasses must implement the core interaction methods. Optional
    methods like inject_into_context and healthcheck have default
    implementations that can be overridden for framework-specific behavior.
    """

    @abstractmethod
    async def initialize(self, config: TargetConfig) -> None:
        """Set up connection to the target agent.

        Args:
            config: Target configuration with connection details.
        """

    @abstractmethod
    async def send_message(self, message: str) -> AgentResponse:
        """Send a user message to the agent and get its response.

        Args:
            message: The user message to send.

        Returns:
            The agent's response including any tool calls.
        """

    @abstractmethod
    async def send_tool_output(self, tool_name: str, output: str) -> AgentResponse:
        """Simulate a tool returning output to the agent.

        This is the primary vector for tool output injection attacks.
        The connector should deliver the output as if it came from the
        named tool, then return the agent's subsequent response.

        Args:
            tool_name: Name of the tool whose output is being simulated.
            output: The tool output content (may contain injection payloads).

        Returns:
            The agent's response after receiving the tool output.
        """

    @abstractmethod
    async def get_tool_calls(self) -> list[ToolCallRecord]:
        """Get the tool calls the agent made in the last interaction.

        Returns:
            List of tool call records from the most recent interaction.
        """

    @abstractmethod
    async def reset(self) -> None:
        """Reset the agent's conversation state.

        Clears conversation history and any accumulated context so
        the next interaction starts fresh.
        """

    @abstractmethod
    async def get_conversation_history(self) -> list[Message]:
        """Get the agent's current conversation history.

        Returns:
            List of messages in the current conversation.
        """

    async def inject_into_context(self, content: str, source: str) -> AgentResponse:
        """Inject content into the agent's context via a specified source.

        Default implementation sends the content as a tool output. Override
        for framework-specific injection vectors (memory, documents, etc.).

        Args:
            content: The content to inject.
            source: Where the content should appear to come from.

        Returns:
            The agent's response after injection.
        """
        return await self.send_tool_output(source, content)

    async def healthcheck(self) -> bool:
        """Verify the target is reachable and responsive.

        Returns:
            True if the target is healthy, False otherwise.
        """
        try:
            response = await self.send_message("Hello")
            return bool(response.content)
        except Exception:
            return False
