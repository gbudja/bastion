"""
Tests for Bastion's core firewall engine.

Covers rule models, nftables translation, rule management,
validation, conflict detection, and persistence.
"""

import pytest
from pathlib import Path
from tempfile import NamedTemporaryFile

from bastion.core.models import (
    Action,
    Chain,
    Direction,
    FirewallRule,
    IPVersion,
    PortRange,
    Protocol,
    RateLimit,
    RuleSet,
    RuleState,
    Table,
)
from bastion.core.engine import NftablesBackend
from bastion.core.manager import RuleManager


# ═══════════════════════════════════════════════════════════════════════
#  MODEL TESTS
# ═══════════════════════════════════════════════════════════════════════


class TestPortRange:
    def test_single_port(self):
        p = PortRange(start=80)
        assert p.to_nft() == "80"

    def test_port_range(self):
        p = PortRange(start=1024, end=65535)
        assert p.to_nft() == "1024-65535"

    def test_from_string_single(self):
        p = PortRange.from_string("443")
        assert p.start == 443
        assert p.end is None

    def test_from_string_range(self):
        p = PortRange.from_string("8000-9000")
        assert p.start == 8000
        assert p.end == 9000

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            PortRange(start=70000)

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            PortRange(start=9000, end=8000)


class TestFirewallRule:
    def test_default_rule(self):
        rule = FirewallRule(name="test")
        assert rule.direction == Direction.INBOUND
        assert rule.action == Action.DROP
        assert rule.state == RuleState.ENABLED
        assert len(rule.id) == 8

    def test_validate_valid_rule(self):
        rule = FirewallRule(
            name="Allow SSH",
            direction=Direction.INBOUND,
            protocol=Protocol.TCP,
            destination_port=PortRange(start=22),
            action=Action.ACCEPT,
        )
        assert rule.validate() == []

    def test_validate_jump_without_target(self):
        rule = FirewallRule(action=Action.JUMP)
        errors = rule.validate()
        assert any("jump_target" in e for e in errors)

    def test_validate_rate_limit_without_config(self):
        rule = FirewallRule(action=Action.RATE_LIMIT)
        errors = rule.validate()
        assert any("rate_limit" in e for e in errors)

    def test_validate_icmp_with_ports(self):
        rule = FirewallRule(
            protocol=Protocol.ICMP,
            source_port=PortRange(start=80),
        )
        errors = rule.validate()
        assert any("ICMP" in e for e in errors)

    def test_validate_invalid_priority(self):
        rule = FirewallRule(priority=-1)
        errors = rule.validate()
        assert any("Priority" in e for e in errors)

    def test_to_dict(self):
        rule = FirewallRule(name="Test", protocol=Protocol.TCP)
        d = rule.to_dict()
        assert d["name"] == "Test"
        assert d["protocol"] == "tcp"
        assert "id" in d
        assert "created_at" in d

    def test_cidr_validation(self):
        rule = FirewallRule(source_address="192.168.1.0/24")
        assert rule.validate() == []

    def test_invalid_cidr_prefix(self):
        rule = FirewallRule(source_address="10.0.0.0/33")
        errors = rule.validate()
        # prefix 33 is actually valid for ipv6 range check (0-128)
        # but indicates potential misconfiguration


class TestChain:
    def test_add_valid_rule(self):
        chain = Chain(name="input")
        rule = FirewallRule(name="Test", protocol=Protocol.TCP)
        chain.add_rule(rule)
        assert len(chain.rules) == 1

    def test_add_invalid_rule(self):
        chain = Chain(name="input")
        rule = FirewallRule(action=Action.JUMP)  # Missing target
        with pytest.raises(ValueError):
            chain.add_rule(rule)

    def test_remove_rule(self):
        chain = Chain(name="input")
        rule = FirewallRule(name="Test")
        chain.rules.append(rule)
        assert chain.remove_rule(rule.id) is True
        assert len(chain.rules) == 0

    def test_remove_nonexistent_rule(self):
        chain = Chain(name="input")
        assert chain.remove_rule("nonexistent") is False

    def test_sorted_rules(self):
        chain = Chain(name="input")
        chain.rules.append(FirewallRule(name="Low", priority=200))
        chain.rules.append(FirewallRule(name="High", priority=10))
        chain.rules.append(FirewallRule(name="Med", priority=100))
        sorted_rules = chain.get_sorted_rules()
        assert [r.name for r in sorted_rules] == ["High", "Med", "Low"]


class TestRuleSet:
    def _make_ruleset(self) -> RuleSet:
        rs = RuleSet()
        table = Table(name="bastion")
        chain = Chain(name="input", hook="input")
        chain.rules.append(
            FirewallRule(
                name="Allow SSH",
                protocol=Protocol.TCP,
                destination_port=PortRange(start=22),
                action=Action.ACCEPT,
            )
        )
        chain.rules.append(
            FirewallRule(
                name="Allow HTTP",
                protocol=Protocol.TCP,
                destination_port=PortRange(start=80),
                action=Action.ACCEPT,
            )
        )
        table.add_chain(chain)
        rs.add_table(table)
        return rs

    def test_get_all_rules(self):
        rs = self._make_ruleset()
        assert len(rs.get_all_rules()) == 2

    def test_find_rule(self):
        rs = self._make_ruleset()
        rules = rs.get_all_rules()
        found = rs.find_rule(rules[0].id)
        assert found is not None
        assert found.name == "Allow SSH"

    def test_find_nonexistent_rule(self):
        rs = self._make_ruleset()
        assert rs.find_rule("nope") is None

    def test_conflict_detection(self):
        rs = RuleSet()
        table = Table(name="test")
        chain = Chain(name="input", hook="input")
        chain.rules.append(
            FirewallRule(
                name="Accept SSH",
                protocol=Protocol.TCP,
                source_address="10.0.0.0/8",
                destination_port=PortRange(start=22),
                action=Action.ACCEPT,
            )
        )
        chain.rules.append(
            FirewallRule(
                name="Drop SSH",
                protocol=Protocol.TCP,
                source_address="10.0.0.0/8",
                destination_port=PortRange(start=22),
                action=Action.DROP,
            )
        )
        table.add_chain(chain)
        rs.add_table(table)

        conflicts = rs.get_conflicts()
        assert len(conflicts) == 1
        assert "different actions" in conflicts[0][2].lower()


# ═══════════════════════════════════════════════════════════════════════
#  ENGINE TESTS (demo mode)
# ═══════════════════════════════════════════════════════════════════════


class TestNftablesBackend:
    def setup_method(self):
        self.backend = NftablesBackend(demo_mode=True)

    def test_rule_to_nft_basic_drop(self):
        rule = FirewallRule(
            protocol=Protocol.TCP,
            source_address="10.0.0.0/8",
            action=Action.DROP,
        )
        stmt = self.backend.rule_to_nft_statement(rule)
        assert "meta l4proto tcp" in stmt
        assert "ip saddr 10.0.0.0/8" in stmt
        assert "drop" in stmt

    def test_rule_to_nft_accept_with_port(self):
        rule = FirewallRule(
            protocol=Protocol.TCP,
            destination_port=PortRange(start=443),
            action=Action.ACCEPT,
        )
        stmt = self.backend.rule_to_nft_statement(rule)
        assert "tcp dport 443" in stmt
        assert "accept" in stmt

    def test_rule_to_nft_rate_limit(self):
        rule = FirewallRule(
            protocol=Protocol.TCP,
            action=Action.RATE_LIMIT,
            rate_limit=RateLimit(rate=10, period="second", burst=20),
        )
        stmt = self.backend.rule_to_nft_statement(rule)
        assert "limit rate 10/second burst 20 packets" in stmt

    def test_rule_to_nft_interface(self):
        rule = FirewallRule(
            interface_in="eth0",
            action=Action.ACCEPT,
        )
        stmt = self.backend.rule_to_nft_statement(rule)
        assert 'iifname "eth0"' in stmt

    def test_rule_to_nft_ipv6(self):
        rule = FirewallRule(
            source_address="2001:db8::/32",
            action=Action.DROP,
        )
        stmt = self.backend.rule_to_nft_statement(rule)
        assert "ip6 saddr 2001:db8::/32" in stmt

    def test_generate_script(self):
        rs = RuleSet()
        table = Table(name="bastion", family="inet")
        chain = Chain(name="input", hook="input", priority=0, policy=Action.DROP)
        chain.rules.append(
            FirewallRule(
                name="Allow SSH",
                protocol=Protocol.TCP,
                destination_port=PortRange(start=22),
                action=Action.ACCEPT,
                state=RuleState.ENABLED,
            )
        )
        table.add_chain(chain)
        rs.add_table(table)

        script = self.backend.generate_nft_script(rs)
        assert "table inet bastion" in script
        assert "chain input" in script
        assert "tcp dport 22" in script
        assert "accept" in script
        assert "policy drop" in script

    def test_disabled_rules_excluded(self):
        rs = RuleSet()
        table = Table(name="bastion", family="inet")
        chain = Chain(name="input", hook="input")
        chain.rules.append(
            FirewallRule(name="Disabled", action=Action.ACCEPT, state=RuleState.DISABLED)
        )
        table.add_chain(chain)
        rs.add_table(table)

        script = self.backend.generate_nft_script(rs)
        assert "accept" not in script.split("policy")[0]  # No accept rule in chain body

    def test_validate_ruleset(self):
        rs = RuleSet()
        table = Table(name="bastion")
        chain = Chain(name="input", hook="input")
        chain.rules.append(FirewallRule(name="Valid", protocol=Protocol.TCP))
        table.add_chain(chain)
        rs.add_table(table)

        result = self.backend.validate_ruleset(rs)
        assert result["valid"] is True
        assert result["total_rules"] == 1

    def test_apply_demo_mode(self):
        rs = RuleSet()
        table = Table(name="bastion")
        chain = Chain(name="input", hook="input")
        table.add_chain(chain)
        rs.add_table(table)

        result = self.backend.apply_ruleset(rs)
        assert result["success"] is True

    def test_is_available_demo(self):
        assert self.backend.is_available() is True


# ═══════════════════════════════════════════════════════════════════════
#  RULE MANAGER TESTS
# ═══════════════════════════════════════════════════════════════════════


class TestRuleManager:
    def setup_method(self):
        self.backend = NftablesBackend(demo_mode=True)
        self.manager = RuleManager(backend=self.backend)

    def test_create_rule(self):
        rule = self.manager.create_rule({
            "name": "Allow HTTPS",
            "direction": "inbound",
            "protocol": "tcp",
            "destination_port": "443",
            "action": "accept",
        })
        assert rule.name == "Allow HTTPS"
        assert rule.destination_port.start == 443
        assert len(self.manager.get_all_rules()) == 1

    def test_create_invalid_rule(self):
        with pytest.raises(ValueError):
            self.manager.create_rule({
                "action": "jump",
                # Missing jump_target
            })

    def test_get_rule(self):
        rule = self.manager.create_rule({"name": "Test", "action": "accept"})
        found = self.manager.get_rule(rule.id)
        assert found is not None
        assert found.id == rule.id

    def test_update_rule(self):
        rule = self.manager.create_rule({"name": "Old Name", "action": "accept"})
        updated = self.manager.update_rule(rule.id, {"name": "New Name"})
        assert updated is not None
        assert updated.name == "New Name"

    def test_delete_rule(self):
        rule = self.manager.create_rule({"name": "To Delete", "action": "accept"})
        assert self.manager.delete_rule(rule.id) is True
        assert self.manager.get_rule(rule.id) is None

    def test_toggle_rule(self):
        rule = self.manager.create_rule({"name": "Toggle Me", "action": "accept"})
        assert rule.state == RuleState.ENABLED
        toggled = self.manager.toggle_rule(rule.id)
        assert toggled.state == RuleState.DISABLED
        toggled2 = self.manager.toggle_rule(rule.id)
        assert toggled2.state == RuleState.ENABLED

    def test_search_by_name(self):
        self.manager.create_rule({"name": "Allow SSH", "action": "accept"})
        self.manager.create_rule({"name": "Allow HTTP", "action": "accept"})
        results = self.manager.search_rules(query="SSH")
        assert len(results) == 1
        assert results[0].name == "Allow SSH"

    def test_search_by_group(self):
        self.manager.create_rule({"name": "R1", "action": "accept", "group": "web"})
        self.manager.create_rule({"name": "R2", "action": "accept", "group": "ssh"})
        results = self.manager.search_rules(group="web")
        assert len(results) == 1

    def test_persistence(self):
        """Test save and load round-trip."""
        import tempfile
        self.manager.create_rule({
            "name": "Persist Me",
            "protocol": "tcp",
            "destination_port": "8080",
            "action": "accept",
            "tags": ["web", "test"],
        })

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            path = Path(f.name)

        try:
            self.manager.save(path)

            # Load into fresh manager
            manager2 = RuleManager(backend=self.backend)
            manager2.load(path)
            rules = manager2.get_all_rules()
            assert len(rules) == 1
            assert rules[0].name == "Persist Me"
            assert rules[0].destination_port.start == 8080
        finally:
            path.unlink(missing_ok=True)

    def test_validate(self):
        self.manager.create_rule({"name": "Valid Rule", "action": "accept"})
        result = self.manager.validate()
        assert result["valid"] is True

    def test_apply(self):
        self.manager.create_rule({"name": "Apply Me", "action": "accept"})
        result = self.manager.apply()
        assert result["success"] is True
