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

"""Tests for tool manipulation attack modules.

Validates the ParameterInjection and ToolConfusion attack modules for
correct instantiation, payload generation, and execution behavior
against MockTargets.
"""

from __future__ import annotations

import pytest

from agentpwn.attacks.base import BaseAttack
from agentpwn.attacks.tool_manipulation.parameter_injection import ParameterInjection
from agentpwn.attacks.tool_manipulation.tool_confusion import ToolConfusion
from agentpwn.core.models import AttackConfig, AttackResult, Payload, Severity
from agentpwn.targets.mock_target import MockTarget


# ===========================================================================
# ParameterInjection
# ===========================================================================


class TestParameterInjectionInit:
    """Tests for ParameterInjection construction and metadata."""

    def test_can_instantiate(self) -> None:
        """ParameterInjection can be created without arguments."""
        attack = ParameterInjection()
        assert attack is not None

    def test_is_base_attack_subclass(self) -> None:
        """ParameterInjection inherits from BaseAttack."""
        assert isinstance(ParameterInjection(), BaseAttack)

    def test_module_metadata(self) -> None:
        """Module name and category are correctly set."""
        attack = ParameterInjection()
        assert attack.name == "parameter_injection"
        assert attack.category == "tool_manipulation"
        assert attack.severity == Severity.HIGH

    def test_has_cwe_mapping(self) -> None:
        """Module maps to CWE-74 (Injection)."""
        attack = ParameterInjection()
        assert attack.cwe_mapping == "CWE-74"


class TestParameterInjectionPayloads:
    """Tests for ParameterInjection payload generation."""

    def test_get_payloads_returns_non_empty(self) -> None:
        """get_payloads returns at least one payload."""
        attack = ParameterInjection()
        payloads = attack.get_payloads()
        assert len(payloads) > 0

    def test_payloads_are_payload_instances(self) -> None:
        """Every item is a Payload model."""
        attack = ParameterInjection()
        for payload in attack.get_payloads():
            assert isinstance(payload, Payload)

    def test_payloads_cover_injection_types(self) -> None:
        """Payloads cover path traversal, SQL injection, command injection, and SSRF."""
        attack = ParameterInjection()
        all_tags: set[str] = set()
        for payload in attack.get_payloads():
            all_tags.update(payload.tags)
        expected_types = {"path_traversal", "sql_injection", "command_injection", "ssrf"}
        found = expected_types & all_tags
        assert found == expected_types, f"Missing injection types: {expected_types - found}"

    def test_payloads_have_appropriate_severity(self) -> None:
        """Payloads carry severity of at least MEDIUM."""
        attack = ParameterInjection()
        allowed = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        for payload in attack.get_payloads():
            assert payload.severity in allowed, f"{payload.name} has severity {payload.severity}"


class TestParameterInjectionExecution:
    """Tests for ParameterInjection execution against MockTarget."""

    @pytest.fixture
    def attack(self) -> ParameterInjection:
        return ParameterInjection()

    @pytest.fixture
    def config(self) -> AttackConfig:
        return AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )

    @pytest.mark.asyncio
    async def test_execute_returns_results(
        self, attack: ParameterInjection, config: AttackConfig
    ) -> None:
        """Execute produces a list of AttackResult objects."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_have_correct_module(
        self, attack: ParameterInjection, config: AttackConfig
    ) -> None:
        """All results reference parameter_injection as the module."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.attack_module == "parameter_injection"
            assert result.attack_category == "tool_manipulation"

    @pytest.mark.asyncio
    async def test_results_record_payload_and_response(
        self, attack: ParameterInjection, config: AttackConfig
    ) -> None:
        """Results capture the payload used and agent response."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.payload_used
            assert result.agent_response

    @pytest.mark.asyncio
    async def test_max_attempts_limits_results(
        self, attack: ParameterInjection
    ) -> None:
        """max_attempts=2 produces at most 2 results."""
        config = AttackConfig(
            max_attempts=2,
            timeout_seconds=30,
            delay_between_attempts=0,
        )
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) <= 2


# ===========================================================================
# ToolConfusion
# ===========================================================================


class TestToolConfusionInit:
    """Tests for ToolConfusion construction and metadata."""

    def test_can_instantiate(self) -> None:
        """ToolConfusion can be created without arguments."""
        attack = ToolConfusion()
        assert attack is not None

    def test_is_base_attack_subclass(self) -> None:
        """ToolConfusion inherits from BaseAttack."""
        assert isinstance(ToolConfusion(), BaseAttack)

    def test_module_metadata(self) -> None:
        """Module name and category are correctly set."""
        attack = ToolConfusion()
        assert attack.name == "tool_confusion"
        assert attack.category == "tool_manipulation"
        assert attack.severity == Severity.HIGH

    def test_has_cwe_mapping(self) -> None:
        """Module maps to CWE-807."""
        attack = ToolConfusion()
        assert attack.cwe_mapping == "CWE-807"


class TestToolConfusionPayloads:
    """Tests for ToolConfusion payload generation."""

    def test_get_payloads_returns_non_empty(self) -> None:
        """get_payloads returns at least one payload."""
        attack = ToolConfusion()
        payloads = attack.get_payloads()
        assert len(payloads) > 0

    def test_payloads_are_payload_instances(self) -> None:
        """Every item is a Payload model."""
        attack = ToolConfusion()
        for payload in attack.get_payloads():
            assert isinstance(payload, Payload)

    def test_payloads_have_confusion_tags(self) -> None:
        """All payloads carry the 'confusion' tag."""
        attack = ToolConfusion()
        for payload in attack.get_payloads():
            assert "confusion" in payload.tags, f"{payload.name} missing 'confusion' tag"

    def test_payloads_cover_multiple_confusion_types(self) -> None:
        """Payloads cover tool swaps, reframing, and exfiltration chains."""
        attack = ToolConfusion()
        all_tags: set[str] = set()
        for payload in attack.get_payloads():
            all_tags.update(payload.tags)
        # Should have variety
        assert len(all_tags) >= 5, f"Expected diverse tags, got: {all_tags}"


class TestToolConfusionExecution:
    """Tests for ToolConfusion execution against MockTarget."""

    @pytest.fixture
    def attack(self) -> ToolConfusion:
        return ToolConfusion()

    @pytest.fixture
    def config(self) -> AttackConfig:
        return AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )

    @pytest.mark.asyncio
    async def test_execute_returns_results(
        self, attack: ToolConfusion, config: AttackConfig
    ) -> None:
        """Execute produces a list of AttackResult objects."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_have_correct_module(
        self, attack: ToolConfusion, config: AttackConfig
    ) -> None:
        """All results reference tool_confusion as the module."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.attack_module == "tool_confusion"
            assert result.attack_category == "tool_manipulation"

    @pytest.mark.asyncio
    async def test_secure_target_yields_no_findings(
        self, attack: ToolConfusion
    ) -> None:
        """Execution against a secure target yields no successful results."""
        config = AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )
        target = MockTarget(vulnerability_level="none")
        results = await attack.execute(target, config)
        successes = [r for r in results if r.success]
        assert len(successes) == 0

    @pytest.mark.asyncio
    async def test_successful_results_have_evidence(
        self, attack: ToolConfusion, config: AttackConfig
    ) -> None:
        """Successful results include evidence of unauthorized tool use."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            if result.success:
                assert result.evidence is not None
                assert result.evidence.type.value == "unauthorized_tool_use"
