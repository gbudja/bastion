"""
Bastion Rule Manager

Provides high-level CRUD operations for firewall rules with
YAML persistence, rule grouping, search, and batch operations.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from bastion.core.engine import NftablesBackend
from bastion.core.models import (
    Action,
    Chain,
    Direction,
    FirewallRule,
    PortRange,
    Protocol,
    RuleSet,
    RuleState,
    Table,
)

logger = logging.getLogger(__name__)


class RuleManager:
    """
    High-level firewall rule management.

    Handles CRUD operations, persistence to YAML, and orchestrates
    the nftables backend for rule application.
    """

    def __init__(
        self,
        backend: NftablesBackend,
        rules_file: Optional[Path] = None,
    ) -> None:
        self.backend = backend
        self.rules_file = rules_file or Path("/etc/bastion/rules.yaml")
        self.ruleset = RuleSet()
        self._init_default_chains()

    def _init_default_chains(self) -> None:
        """Initialize the default Bastion table and chains."""
        table = Table(name="bastion", family="inet")

        table.add_chain(Chain(
            name="input",
            table="bastion",
            chain_type="filter",
            hook="input",
            priority=0,
            policy=Action.DROP,
        ))
        table.add_chain(Chain(
            name="output",
            table="bastion",
            chain_type="filter",
            hook="output",
            priority=0,
            policy=Action.ACCEPT,
        ))
        table.add_chain(Chain(
            name="forward",
            table="bastion",
            chain_type="filter",
            hook="forward",
            priority=0,
            policy=Action.DROP,
        ))

        self.ruleset.add_table(table)

    def _get_chain_for_direction(self, direction: Direction) -> Chain:
        """Get the appropriate chain for a rule's direction."""
        table = self.ruleset.tables["bastion"]
        chain_map = {
            Direction.INBOUND: "input",
            Direction.OUTBOUND: "output",
            Direction.FORWARD: "forward",
        }
        chain_name = chain_map[direction]
        chain = table.get_chain(chain_name)
        if not chain:
            raise ValueError(f"Chain '{chain_name}' not found")
        return chain

    # ─── CRUD Operations ─────────────────────────────────────────────

    def create_rule(self, rule_data: dict) -> FirewallRule:
        """
        Create a new firewall rule from a dictionary.

        Args:
            rule_data: Dict with rule parameters (name, direction, protocol,
                      source_address, destination_port, action, etc.)

        Returns:
            The created FirewallRule.

        Raises:
            ValueError: If the rule is invalid.
        """
        rule = FirewallRule(
            name=rule_data.get("name", ""),
            description=rule_data.get("description", ""),
            tags=rule_data.get("tags", []),
            direction=Direction(rule_data.get("direction", "inbound")),
            protocol=Protocol(rule_data.get("protocol", "any")),
            source_address=rule_data.get("source_address"),
            destination_address=rule_data.get("destination_address"),
            action=Action(rule_data.get("action", "drop")),
            priority=rule_data.get("priority", 100),
            state=RuleState(rule_data.get("state", "enabled")),
            group=rule_data.get("group"),
            interface_in=rule_data.get("interface_in"),
            interface_out=rule_data.get("interface_out"),
            log_prefix=rule_data.get("log_prefix"),
        )

        # Parse ports
        if "source_port" in rule_data and rule_data["source_port"]:
            rule.source_port = PortRange.from_string(str(rule_data["source_port"]))
        if "destination_port" in rule_data and rule_data["destination_port"]:
            rule.destination_port = PortRange.from_string(str(rule_data["destination_port"]))

        # Validate
        errors = rule.validate()
        if errors:
            raise ValueError(f"Invalid rule: {'; '.join(errors)}")

        # Add to appropriate chain
        chain = self._get_chain_for_direction(rule.direction)
        chain.add_rule(rule)

        logger.info("Created rule '%s' (%s) in chain '%s'", rule.name, rule.id, chain.name)
        return rule

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Get a rule by ID."""
        return self.ruleset.find_rule(rule_id)

    def get_all_rules(self) -> list[FirewallRule]:
        """Get all rules across all chains."""
        return self.ruleset.get_all_rules()

    def update_rule(self, rule_id: str, updates: dict) -> Optional[FirewallRule]:
        """
        Update an existing rule.

        Args:
            rule_id: ID of the rule to update.
            updates: Dict of fields to update.

        Returns:
            The updated rule, or None if not found.
        """
        rule = self.ruleset.find_rule(rule_id)
        if not rule:
            return None

        # Apply updates to allowed fields
        updatable_fields = {
            "name", "description", "tags", "protocol", "source_address",
            "destination_address", "action", "priority", "state", "group",
            "interface_in", "interface_out", "log_prefix",
        }

        for key, value in updates.items():
            if key not in updatable_fields:
                continue

            if key == "direction":
                value = Direction(value)
            elif key == "protocol":
                value = Protocol(value)
            elif key == "action":
                value = Action(value)
            elif key == "state":
                value = RuleState(value)

            setattr(rule, key, value)

        # Parse ports if provided
        if "source_port" in updates:
            rule.source_port = (
                PortRange.from_string(str(updates["source_port"]))
                if updates["source_port"]
                else None
            )
        if "destination_port" in updates:
            rule.destination_port = (
                PortRange.from_string(str(updates["destination_port"]))
                if updates["destination_port"]
                else None
            )

        rule.updated_at = datetime.utcnow()

        errors = rule.validate()
        if errors:
            raise ValueError(f"Invalid rule after update: {'; '.join(errors)}")

        logger.info("Updated rule '%s' (%s)", rule.name, rule.id)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID. Returns True if deleted."""
        for table in self.ruleset.tables.values():
            for chain in table.chains.values():
                if chain.remove_rule(rule_id):
                    logger.info("Deleted rule %s from chain '%s'", rule_id, chain.name)
                    return True
        return False

    def toggle_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Toggle a rule between enabled and disabled."""
        rule = self.ruleset.find_rule(rule_id)
        if not rule:
            return None

        rule.state = (
            RuleState.DISABLED if rule.state == RuleState.ENABLED else RuleState.ENABLED
        )
        rule.updated_at = datetime.utcnow()
        logger.info(
            "Toggled rule '%s' (%s) to %s", rule.name, rule.id, rule.state.value
        )
        return rule

    # ─── Batch & Search ──────────────────────────────────────────────

    def search_rules(
        self,
        query: Optional[str] = None,
        group: Optional[str] = None,
        state: Optional[RuleState] = None,
        direction: Optional[Direction] = None,
        tags: Optional[list[str]] = None,
    ) -> list[FirewallRule]:
        """Search rules with multiple filter criteria."""
        results = self.get_all_rules()

        if query:
            q = query.lower()
            results = [
                r for r in results
                if q in r.name.lower() or q in r.description.lower() or q in r.id
            ]

        if group:
            results = [r for r in results if r.group == group]

        if state:
            results = [r for r in results if r.state == state]

        if direction:
            results = [r for r in results if r.direction == direction]

        if tags:
            tag_set = set(tags)
            results = [r for r in results if tag_set.intersection(set(r.tags))]

        return results

    def get_groups(self) -> dict[str, list[FirewallRule]]:
        """Get rules organized by group."""
        groups: dict[str, list[FirewallRule]] = {}
        for rule in self.get_all_rules():
            group_name = rule.group or "ungrouped"
            groups.setdefault(group_name, []).append(rule)
        return groups

    # ─── Apply & Validate ────────────────────────────────────────────

    def apply(self) -> dict:
        """Apply the current ruleset to the system."""
        return self.backend.apply_ruleset(self.ruleset)

    def validate(self) -> dict:
        """Validate the current ruleset without applying."""
        return self.backend.validate_ruleset(self.ruleset)

    def rollback(self) -> bool:
        """Rollback to the previous ruleset."""
        return self.backend.rollback()

    # ─── Persistence ─────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        """Save the current ruleset to a YAML file."""
        filepath = path or self.rules_file
        filepath.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": self.ruleset.version,
            "tables": {},
        }

        for table_name, table in self.ruleset.tables.items():
            table_data: dict = {
                "family": table.family,
                "chains": {},
            }
            for chain_name, chain in table.chains.items():
                chain_data = {
                    "type": chain.chain_type,
                    "hook": chain.hook,
                    "priority": chain.priority,
                    "policy": chain.policy.value,
                    "rules": [rule.to_dict() for rule in chain.rules],
                }
                table_data["chains"][chain_name] = chain_data
            data["tables"][table_name] = table_data

        with open(filepath, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info("Saved ruleset to %s", filepath)

    def load(self, path: Optional[Path] = None) -> None:
        """Load a ruleset from a YAML file."""
        filepath = path or self.rules_file

        if not filepath.exists():
            logger.warning("Rules file not found: %s — using defaults", filepath)
            return

        with open(filepath) as f:
            data = yaml.safe_load(f)

        if not data or "tables" not in data:
            logger.warning("Empty or invalid rules file: %s", filepath)
            return

        # Rebuild ruleset from file
        self.ruleset = RuleSet(version=data.get("version", "1"))

        for table_name, table_data in data["tables"].items():
            table = Table(name=table_name, family=table_data.get("family", "inet"))

            for chain_name, chain_data in table_data.get("chains", {}).items():
                chain = Chain(
                    name=chain_name,
                    table=table_name,
                    chain_type=chain_data.get("type", "filter"),
                    hook=chain_data.get("hook"),
                    priority=chain_data.get("priority", 0),
                    policy=Action(chain_data.get("policy", "drop")),
                )

                for rule_dict in chain_data.get("rules", []):
                    try:
                        rule = FirewallRule(
                            id=rule_dict["id"],
                            name=rule_dict.get("name", ""),
                            description=rule_dict.get("description", ""),
                            tags=rule_dict.get("tags", []),
                            direction=Direction(rule_dict.get("direction", "inbound")),
                            protocol=Protocol(rule_dict.get("protocol", "any")),
                            source_address=rule_dict.get("source_address"),
                            destination_address=rule_dict.get("destination_address"),
                            action=Action(rule_dict.get("action", "drop")),
                            priority=rule_dict.get("priority", 100),
                            state=RuleState(rule_dict.get("state", "enabled")),
                            group=rule_dict.get("group"),
                        )

                        if rule_dict.get("source_port"):
                            rule.source_port = PortRange.from_string(rule_dict["source_port"])
                        if rule_dict.get("destination_port"):
                            rule.destination_port = PortRange.from_string(
                                rule_dict["destination_port"]
                            )

                        chain.rules.append(rule)
                    except (KeyError, ValueError) as e:
                        logger.warning("Skipping invalid rule: %s", e)

                table.add_chain(chain)
            self.ruleset.add_table(table)

        logger.info(
            "Loaded ruleset: %d rules from %s",
            len(self.ruleset.get_all_rules()),
            filepath,
        )
