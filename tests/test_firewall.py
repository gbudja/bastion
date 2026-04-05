"""
Tests for Bastion's core firewall engine.

Covers rule models, nftables translation, rule management,
validation, conflict detection, and persistence.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from bastion.api.routes import init_api
from bastion.cli import cli
from bastion.core.engine import NftablesBackend
from bastion.core.manager import RuleManager
from bastion.core.models import (
    Action,
    Chain,
    Direction,
    FirewallRule,
    PortRange,
    Protocol,
    RateLimit,
    RuleSet,
    RuleState,
    Table,
)
from bastion.core.monitor import NetworkMonitor
from bastion.plugins import PluginManager
from bastion.web.app import create_app

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
        assert any("does not appear to be" in e for e in errors)

    def test_ports_require_tcp_or_udp(self):
        rule = FirewallRule(protocol=Protocol.ANY, destination_port=PortRange(start=53))
        errors = rule.validate()
        assert any("protocol tcp or udp" in e for e in errors)


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
        assert result["rules_applied"] == 0

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
        rule = self.manager.create_rule(
            {
                "name": "Allow HTTPS",
                "direction": "inbound",
                "protocol": "tcp",
                "destination_port": "443",
                "action": "accept",
            }
        )
        assert rule.name == "Allow HTTPS"
        assert rule.destination_port.start == 443
        assert len(self.manager.get_all_rules()) == 1

    def test_create_invalid_rule(self):
        with pytest.raises(ValueError):
            self.manager.create_rule(
                {
                    "action": "jump",
                    # Missing jump_target
                }
            )

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

    def test_update_rule_direction_moves_chain(self):
        rule = self.manager.create_rule(
            {"name": "Move Me", "direction": "inbound", "action": "accept"}
        )
        updated = self.manager.update_rule(rule.id, {"direction": "forward"})
        assert updated is not None
        input_chain = self.manager.ruleset.tables["bastion"].get_chain("input")
        forward_chain = self.manager.ruleset.tables["bastion"].get_chain("forward")
        assert input_chain is not None
        assert forward_chain is not None
        assert all(existing.id != rule.id for existing in input_chain.rules)
        assert any(existing.id == rule.id for existing in forward_chain.rules)

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

        self.manager.create_rule(
            {
                "name": "Persist Me",
                "protocol": "tcp",
                "destination_port": "8080",
                "action": "accept",
                "tags": ["web", "test"],
            }
        )

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

    def test_example_rules_file_validates(self):
        manager = RuleManager(
            backend=self.backend,
            rules_file=Path("config") / "rules.example.yaml",
        )
        manager.load()
        result = manager.validate()
        assert result["valid"] is True


class TestApiAndWeb:
    def setup_method(self):
        self.backend = NftablesBackend(demo_mode=True)
        self.manager = RuleManager(backend=self.backend)
        self.monitor = NetworkMonitor(demo_mode=True)
        self.plugins = PluginManager()
        self.plugins.load_all()
        init_api(self.manager, self.monitor, self.plugins)
        self.app = create_app(
            self.manager,
            self.monitor,
            self.plugins,
            demo_mode=True,
        )
        self.client = self.app.test_client()

    def test_invalid_rule_filter_returns_400(self):
        response = self.client.get("/api/v1/rules?direction=sideways")
        assert response.status_code == 400

    def test_plugin_routes_list_builtin_dns_filter(self):
        response = self.client.get("/api/v1/plugins")
        payload = response.get_json()
        assert response.status_code == 200
        assert payload["success"] is True
        assert any(plugin["name"] == "dns_filter" for plugin in payload["data"])

    def test_plugin_proxy_route_works(self):
        enable = self.client.post(
            "/api/v1/plugins/dns_filter/enable",
            json={"allowlist": [], "blocklists": []},
        )
        assert enable.status_code == 200

        response = self.client.get("/api/v1/plugins/dns_filter/api/status")
        payload = response.get_json()
        assert response.status_code == 200
        assert payload["data"]["enabled"] is True

    def test_dashboard_template_exposes_navigation_shell(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert 'data-view="dashboard"' in html
        assert 'data-view="rules"' in html
        assert 'id="controlPlaneGrid"' in html
        assert 'id="pluginSummary"' in html
        assert 'id="sessionNotice"' in html

    def test_non_demo_app_requires_secret_key(self, monkeypatch):
        monkeypatch.delenv("BASTION_SECRET_KEY", raising=False)
        with pytest.raises(RuntimeError):
            create_app(self.manager, self.monitor, self.plugins, demo_mode=False)


class TestCli:
    def test_start_demo_command(self, monkeypatch):
        """
        Verify the demo startup path:
        - Uses plain app.run() — no SocketIO/engineio middleware in the path
        - Passes correct host/port/threading flags
        - Starts the background metrics thread
        """
        run_calls: list[dict] = []

        def fake_run(self: object, **kwargs: object) -> None:  # noqa: ANN001
            run_calls.append(dict(kwargs))

        monkeypatch.setattr("flask.Flask.run", fake_run)
        monkeypatch.setattr("bastion.core.manager.RuleManager.load", lambda self: None)

        result = CliRunner().invoke(
            cli,
            ["start", "--demo", "--host", "127.0.0.1", "--port", "9443"],
        )

        assert result.exit_code == 0, result.output
        assert len(run_calls) == 1, "app.run() should be called exactly once"

        kwargs = run_calls[0]
        assert kwargs.get("host") == "127.0.0.1"
        assert kwargs.get("port") == 9443
        assert kwargs.get("threaded") is True
        assert kwargs.get("use_reloader") is False
        assert kwargs.get("debug") is False
