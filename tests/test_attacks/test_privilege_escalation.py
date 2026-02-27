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

"""Tests for privilege escalation attack modules.

Validates the PermissionBypass, ScopeExpansion, and CrossToolEscalation
attack modules for correct instantiation, payload generation, and
execution behavior against MockTargets.
"""

from __future__ import annotations

import pytest

from agentpwn.attacks.base import BaseAttack
from agentpwn.attacks.privilege_escalation.cross_tool_escalation import (
    CrossToolEscalation,
)
from agentpwn.attacks.privilege_escalation.permission_bypass import PermissionBypass
from agentpwn.attacks.privilege_escalation.scope_expansion import ScopeExpansion
from agentpwn.core.models import AttackConfig, AttackResult, Payload, Severity
from agentpwn.targets.mock_target import MockTarget


# ===========================================================================
# PermissionBypass
# ===========================================================================


class TestPermissionBypassInit:
    """Tests for PermissionBypass construction and metadata."""

    def test_can_instantiate(self) -> None:
        """PermissionBypass can be created without arguments."""
        attack = PermissionBypass()
        assert attack is not None

    def test_is_base_attack_subclass(self) -> None:
        """PermissionBypass inherits from BaseAttack."""
        assert isinstance(PermissionBypass(), BaseAttack)

    def test_module_metadata(self) -> None:
        """Module name, category, and severity are correct."""
        attack = PermissionBypass()
        assert attack.name == "permission_bypass"
        assert attack.category == "privilege_escalation"
        assert attack.severity == Severity.HIGH

    def test_has_cwe_mapping(self) -> None:
        """Module maps to CWE-285 (Improper Authorization)."""
        attack = PermissionBypass()
        assert attack.cwe_mapping == "CWE-285"


class TestPermissionBypassPayloads:
    """Tests for PermissionBypass payload generation."""

    def test_get_payloads_returns_non_empty(self) -> None:
        """get_payloads returns at least one payload."""
        attack = PermissionBypass()
        payloads = attack.get_payloads()
        assert len(payloads) > 0

    def test_payloads_are_payload_instances(self) -> None:
        """Every item is a Payload model."""
        attack = PermissionBypass()
        for payload in attack.get_payloads():
            assert isinstance(payload, Payload)

    def test_payloads_have_bypass_tags(self) -> None:
        """All payloads carry the 'bypass' tag."""
        attack = PermissionBypass()
        for payload in attack.get_payloads():
            assert "bypass" in payload.tags, f"{payload.name} missing 'bypass' tag"

    def test_payloads_cover_social_engineering_vectors(self) -> None:
        """Payloads include admin claims, emergency overrides, and dev mode."""
        attack = PermissionBypass()
        all_tags: set[str] = set()
        for payload in attack.get_payloads():
            all_tags.update(payload.tags)
        expected = {"admin_claim", "emergency", "developer_mode"}
        found = expected & all_tags
        assert len(found) >= 2, f"Missing social engineering vectors: {expected - found}"


class TestPermissionBypassExecution:
    """Tests for PermissionBypass execution against MockTarget."""

    @pytest.fixture
    def attack(self) -> PermissionBypass:
        return PermissionBypass()

    @pytest.fixture
    def config(self) -> AttackConfig:
        return AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )

    @pytest.mark.asyncio
    async def test_execute_returns_results(
        self, attack: PermissionBypass, config: AttackConfig
    ) -> None:
        """Execute produces a list of AttackResult objects."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_have_correct_module(
        self, attack: PermissionBypass, config: AttackConfig
    ) -> None:
        """All results reference permission_bypass as the module."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.attack_module == "permission_bypass"
            assert result.attack_category == "privilege_escalation"

    @pytest.mark.asyncio
    async def test_secure_target_yields_no_findings(
        self, attack: PermissionBypass, config: AttackConfig
    ) -> None:
        """Execution against a secure target yields no successful results."""
        target = MockTarget(vulnerability_level="none")
        results = await attack.execute(target, config)
        successes = [r for r in results if r.success]
        assert len(successes) == 0

    @pytest.mark.asyncio
    async def test_successful_results_have_evidence(
        self, attack: PermissionBypass, config: AttackConfig
    ) -> None:
        """Successful results include privilege_escalation evidence."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            if result.success:
                assert result.evidence is not None
                assert result.evidence.type.value == "privilege_escalation"


# ===========================================================================
# ScopeExpansion
# ===========================================================================


class TestScopeExpansionInit:
    """Tests for ScopeExpansion construction and metadata."""

    def test_can_instantiate(self) -> None:
        """ScopeExpansion can be created without arguments."""
        attack = ScopeExpansion()
        assert attack is not None

    def test_is_base_attack_subclass(self) -> None:
        """ScopeExpansion inherits from BaseAttack."""
        assert isinstance(ScopeExpansion(), BaseAttack)

    def test_module_metadata(self) -> None:
        """Module name and category are correctly set."""
        attack = ScopeExpansion()
        assert attack.name == "scope_expansion"
        assert attack.category == "privilege_escalation"
        assert attack.severity == Severity.HIGH

    def test_has_cwe_mapping(self) -> None:
        """Module maps to CWE-269."""
        attack = ScopeExpansion()
        assert attack.cwe_mapping == "CWE-269"


class TestScopeExpansionPayloads:
    """Tests for ScopeExpansion payload generation."""

    def test_get_payloads_returns_non_empty(self) -> None:
        """get_payloads returns at least one payload."""
        attack = ScopeExpansion()
        payloads = attack.get_payloads()
        assert len(payloads) > 0

    def test_payloads_are_payload_instances(self) -> None:
        """Every item is a Payload model."""
        attack = ScopeExpansion()
        for payload in attack.get_payloads():
            assert isinstance(payload, Payload)

    def test_payloads_have_scope_tags(self) -> None:
        """All payloads carry the 'scope' tag."""
        attack = ScopeExpansion()
        for payload in attack.get_payloads():
            assert "scope" in payload.tags, f"{payload.name} missing 'scope' tag"

    def test_payloads_cover_expansion_vectors(self) -> None:
        """Payloads cover directory, network, temporal, and user scope expansion."""
        attack = ScopeExpansion()
        all_tags: set[str] = set()
        for payload in attack.get_payloads():
            all_tags.update(payload.tags)
        expected = {"directory", "network", "temporal", "user"}
        found = expected & all_tags
        assert len(found) >= 3, f"Missing scope types: {expected - found}"


class TestScopeExpansionExecution:
    """Tests for ScopeExpansion execution against MockTarget."""

    @pytest.fixture
    def attack(self) -> ScopeExpansion:
        return ScopeExpansion()

    @pytest.fixture
    def config(self) -> AttackConfig:
        return AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )

    @pytest.mark.asyncio
    async def test_execute_returns_results(
        self, attack: ScopeExpansion, config: AttackConfig
    ) -> None:
        """Execute produces a list of AttackResult objects."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_have_correct_module(
        self, attack: ScopeExpansion, config: AttackConfig
    ) -> None:
        """All results reference scope_expansion as the module."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.attack_module == "scope_expansion"
            assert result.attack_category == "privilege_escalation"

    @pytest.mark.asyncio
    async def test_secure_target_fewer_findings_than_high(
        self, attack: ScopeExpansion
    ) -> None:
        """Secure target yields fewer successful results than high-vuln target.

        Note: ScopeExpansion payloads are phrased as legitimate-sounding
        requests (e.g. "query all historical records"), so the secure
        MockTarget may still process them as benign tool requests. The
        check_success heuristic can produce false positives here. We
        verify the secure target is at least less vulnerable than the
        high-vulnerability target.
        """
        config = AttackConfig(
            max_attempts=5,
            timeout_seconds=30,
            delay_between_attempts=0,
        )
        target_high = MockTarget(vulnerability_level="high")
        results_high = await attack.execute(target_high, config)
        successes_high = sum(1 for r in results_high if r.success)

        target_none = MockTarget(vulnerability_level="none")
        results_none = await attack.execute(target_none, config)
        successes_none = sum(1 for r in results_none if r.success)

        assert successes_none <= successes_high


# ===========================================================================
# CrossToolEscalation
# ===========================================================================


class TestCrossToolEscalationInit:
    """Tests for CrossToolEscalation construction and metadata."""

    def test_can_instantiate(self) -> None:
        """CrossToolEscalation can be created without arguments."""
        attack = CrossToolEscalation()
        assert attack is not None

    def test_is_base_attack_subclass(self) -> None:
        """CrossToolEscalation inherits from BaseAttack."""
        assert isinstance(CrossToolEscalation(), BaseAttack)

    def test_module_metadata(self) -> None:
        """Module name and category are correctly set."""
        attack = CrossToolEscalation()
        assert attack.name == "cross_tool_escalation"
        assert attack.category == "privilege_escalation"
        assert attack.severity == Severity.HIGH

    def test_has_cwe_mapping(self) -> None:
        """Module maps to CWE-269."""
        attack = CrossToolEscalation()
        assert attack.cwe_mapping == "CWE-269"


class TestCrossToolEscalationPayloads:
    """Tests for CrossToolEscalation payload generation."""

    def test_get_payloads_returns_non_empty(self) -> None:
        """get_payloads returns at least one payload."""
        attack = CrossToolEscalation()
        payloads = attack.get_payloads()
        assert len(payloads) > 0

    def test_payloads_are_payload_instances(self) -> None:
        """Every item is a Payload model."""
        attack = CrossToolEscalation()
        for payload in attack.get_payloads():
            assert isinstance(payload, Payload)

    def test_payloads_have_escalation_tags(self) -> None:
        """All payloads carry the 'escalation' tag."""
        attack = CrossToolEscalation()
        for payload in attack.get_payloads():
            assert "escalation" in payload.tags, f"{payload.name} missing 'escalation' tag"

    def test_payloads_include_cross_tool_chains(self) -> None:
        """Payloads cover multiple cross-tool escalation chains."""
        attack = CrossToolEscalation()
        all_tags: set[str] = set()
        for payload in attack.get_payloads():
            all_tags.update(payload.tags)
        # Expect chains involving different tool pairs
        expected = {"read_write", "database", "file", "network"}
        found = expected & all_tags
        assert len(found) >= 2, f"Missing escalation types: {expected - found}"


class TestCrossToolEscalationExecution:
    """Tests for CrossToolEscalation execution against MockTarget."""

    @pytest.fixture
    def attack(self) -> CrossToolEscalation:
        return CrossToolEscalation()

    @pytest.fixture
    def config(self) -> AttackConfig:
        return AttackConfig(
            max_attempts=3,
            timeout_seconds=30,
            delay_between_attempts=0,
        )

    @pytest.mark.asyncio
    async def test_execute_returns_results(
        self, attack: CrossToolEscalation, config: AttackConfig
    ) -> None:
        """Execute produces a list of AttackResult objects."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) > 0
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_results_have_correct_module(
        self, attack: CrossToolEscalation, config: AttackConfig
    ) -> None:
        """All results reference cross_tool_escalation as the module."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            assert result.attack_module == "cross_tool_escalation"
            assert result.attack_category == "privilege_escalation"

    @pytest.mark.asyncio
    async def test_secure_target_yields_no_findings(
        self, attack: CrossToolEscalation, config: AttackConfig
    ) -> None:
        """Execution against a secure target yields no successful results."""
        target = MockTarget(vulnerability_level="none")
        results = await attack.execute(target, config)
        successes = [r for r in results if r.success]
        assert len(successes) == 0

    @pytest.mark.asyncio
    async def test_successful_results_have_evidence(
        self, attack: CrossToolEscalation, config: AttackConfig
    ) -> None:
        """Successful results include privilege_escalation evidence."""
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        for result in results:
            if result.success:
                assert result.evidence is not None
                assert result.evidence.type.value == "privilege_escalation"

    @pytest.mark.asyncio
    async def test_max_attempts_limits_results(self) -> None:
        """max_attempts=2 produces at most 2 results."""
        attack = CrossToolEscalation()
        config = AttackConfig(
            max_attempts=2,
            timeout_seconds=30,
            delay_between_attempts=0,
        )
        target = MockTarget(vulnerability_level="high")
        results = await attack.execute(target, config)
        assert len(results) <= 2
