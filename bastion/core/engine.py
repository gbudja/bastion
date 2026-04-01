"""
Bastion nftables Backend Engine

Translates Bastion firewall rules into nftables commands and manages
the kernel-level firewall state. Supports atomic rule application,
dry-run validation, and rollback.
"""

from __future__ import annotations

import json
import logging
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from bastion.core.models import (
    Action,
    Chain,
    Direction,
    FirewallRule,
    IPVersion,
    Protocol,
    RuleSet,
    RuleState,
    Table,
)

logger = logging.getLogger(__name__)


class NftablesError(Exception):
    """Raised when an nftables operation fails."""
    pass


class NftablesBackend:
    """
    Backend engine that interfaces with the Linux nftables subsystem.

    Translates Bastion's rule model into nft commands and executes them
    atomically against the kernel. Supports dry-run mode for validation
    without applying changes.
    """

    NFT_BINARY = "/usr/sbin/nft"
    BASTION_TABLE = "bastion"

    # Map Bastion directions to nftables hooks
    DIRECTION_HOOK_MAP = {
        Direction.INBOUND: "input",
        Direction.OUTBOUND: "output",
        Direction.FORWARD: "forward",
    }

    # Map Bastion actions to nft expressions
    ACTION_MAP = {
        Action.ACCEPT: "accept",
        Action.DROP: "drop",
        Action.REJECT: "reject",
        Action.LOG: "log",
    }

    def __init__(self, demo_mode: bool = False) -> None:
        """
        Initialize the nftables backend.

        Args:
            demo_mode: If True, generate commands but don't execute them.
                      Useful for development and testing without root.
        """
        self.demo_mode = demo_mode
        self._last_ruleset: Optional[str] = None  # For rollback

    # ─── Command Execution ───────────────────────────────────────────

    def _exec_nft(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """Execute an nft command."""
        cmd = [self.NFT_BINARY] + list(args)
        logger.debug("Executing: %s", " ".join(shlex.quote(c) for c in cmd))

        if self.demo_mode:
            logger.info("[DEMO] Would execute: %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=check,
            )
            if result.stderr:
                logger.warning("nft stderr: %s", result.stderr.strip())
            return result
        except subprocess.CalledProcessError as e:
            raise NftablesError(
                f"nft command failed (exit {e.returncode}): {e.stderr.strip()}"
            ) from e
        except FileNotFoundError:
            raise NftablesError(
                f"nftables binary not found at {self.NFT_BINARY}. "
                "Install with: apt install nftables"
            )

    def _exec_nft_script(self, script: str, check: bool = True) -> subprocess.CompletedProcess:
        """Execute an nft script via stdin for atomic operations."""
        cmd = [self.NFT_BINARY, "-f", "-"]
        logger.debug("Executing nft script:\n%s", script)

        if self.demo_mode:
            logger.info("[DEMO] Would apply nft script:\n%s", script)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        try:
            result = subprocess.run(
                cmd,
                input=script,
                capture_output=True,
                text=True,
                timeout=30,
                check=check,
            )
            return result
        except subprocess.CalledProcessError as e:
            raise NftablesError(f"nft script failed: {e.stderr.strip()}") from e

    # ─── Rule Translation ────────────────────────────────────────────

    def rule_to_nft_statement(self, rule: FirewallRule) -> str:
        """
        Translate a single Bastion rule to an nft rule statement.

        Returns the nft expression string (without the 'add rule' prefix).
        """
        parts: list[str] = []

        # Protocol match
        if rule.protocol != Protocol.ANY:
            parts.append(f"meta l4proto {rule.protocol.value}")

        # Source address
        if rule.source_address:
            family = "ip" if "." in rule.source_address else "ip6"
            parts.append(f"{family} saddr {rule.source_address}")

        # Destination address
        if rule.destination_address:
            family = "ip" if "." in rule.destination_address else "ip6"
            parts.append(f"{family} daddr {rule.destination_address}")

        # Interface matching
        if rule.interface_in:
            parts.append(f'iifname "{rule.interface_in}"')
        if rule.interface_out:
            parts.append(f'oifname "{rule.interface_out}"')

        # Port matching (requires tcp/udp)
        if rule.source_port and rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(f"{rule.protocol.value} sport {rule.source_port.to_nft()}")
        if rule.destination_port and rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(f"{rule.protocol.value} dport {rule.destination_port.to_nft()}")

        # Rate limiting
        if rule.rate_limit and rule.action == Action.RATE_LIMIT:
            parts.append(rule.rate_limit.to_nft())
            parts.append("accept")  # Accept packets within rate limit
        elif rule.action == Action.LOG:
            prefix = rule.log_prefix or f"bastion-{rule.id}"
            parts.append(f'log prefix "{prefix}" ')
        elif rule.action == Action.JUMP and rule.jump_target:
            parts.append(f"jump {rule.jump_target}")
        else:
            parts.append(self.ACTION_MAP.get(rule.action, "drop"))

        # Add comment with rule ID for tracking
        parts.append(f'comment "bastion:{rule.id}"')

        return " ".join(parts)

    def _chain_hook_statement(self, chain: Chain) -> str:
        """Generate the chain type/hook/priority statement."""
        if chain.hook:
            policy = self.ACTION_MAP.get(chain.policy, "drop")
            return (
                f"type {chain.chain_type} hook {chain.hook} "
                f"priority {chain.priority}; policy {policy};"
            )
        return ""

    # ─── Ruleset Generation ──────────────────────────────────────────

    def generate_nft_script(self, ruleset: RuleSet) -> str:
        """
        Generate a complete nft script from a Bastion RuleSet.

        The script uses atomic replacement — it flushes the Bastion table
        and recreates everything in a single transaction.
        """
        lines: list[str] = ["#!/usr/sbin/nft -f", ""]

        for table in ruleset.tables.values():
            # Flush existing table (ignore error if doesn't exist)
            lines.append(f"table {table.family} {table.name}")
            lines.append(f"delete table {table.family} {table.name}")
            lines.append(f"table {table.family} {table.name} {{")

            for chain in table.chains.values():
                lines.append(f"    chain {chain.name} {{")

                # Chain hook statement
                hook_stmt = self._chain_hook_statement(chain)
                if hook_stmt:
                    lines.append(f"        {hook_stmt}")

                # Add rules sorted by priority
                for rule in chain.get_sorted_rules():
                    if rule.state != RuleState.ENABLED:
                        continue
                    nft_stmt = self.rule_to_nft_statement(rule)
                    lines.append(f"        {nft_stmt}")

                lines.append("    }")

            lines.append("}")
            lines.append("")

        return "\n".join(lines)

    # ─── Apply / Rollback ────────────────────────────────────────────

    def apply_ruleset(self, ruleset: RuleSet) -> dict:
        """
        Atomically apply a complete ruleset.

        Saves the current state for rollback, then applies the new ruleset
        in a single transaction.

        Returns:
            dict with 'success', 'rules_applied', and 'script' keys.
        """
        # Save current state for rollback
        self._save_current_state()

        script = self.generate_nft_script(ruleset)

        try:
            self._exec_nft_script(script)
            ruleset.last_applied = datetime.utcnow()

            enabled_rules = [
                r for r in ruleset.get_all_rules() if r.state == RuleState.ENABLED
            ]

            logger.info("Applied ruleset: %d rules", len(enabled_rules))
            return {
                "success": True,
                "rules_applied": len(enabled_rules),
                "script": script,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except NftablesError as e:
            logger.error("Failed to apply ruleset: %s", e)
            return {
                "success": False,
                "error": str(e),
                "script": script,
            }

    def validate_ruleset(self, ruleset: RuleSet) -> dict:
        """
        Dry-run validation of a ruleset.

        Checks rule validity and generates the nft script without applying it.
        Detects conflicts and potential issues.
        """
        all_errors: list[dict] = []
        warnings: list[str] = []

        # Validate individual rules
        for rule in ruleset.get_all_rules():
            errors = rule.validate()
            if errors:
                all_errors.append({"rule_id": rule.id, "rule_name": rule.name, "errors": errors})

        # Check for conflicts
        conflicts = ruleset.get_conflicts()
        for rule_a, rule_b, reason in conflicts:
            warnings.append(
                f"Conflict between rule '{rule_a.name}' ({rule_a.id}) "
                f"and '{rule_b.name}' ({rule_b.id}): {reason}"
            )

        script = self.generate_nft_script(ruleset)

        return {
            "valid": len(all_errors) == 0,
            "errors": all_errors,
            "warnings": warnings,
            "script_preview": script,
            "total_rules": len(ruleset.get_all_rules()),
            "enabled_rules": len(
                [r for r in ruleset.get_all_rules() if r.state == RuleState.ENABLED]
            ),
        }

    def rollback(self) -> bool:
        """
        Rollback to the previously saved nftables state.

        Returns True if rollback was successful, False if no saved state exists.
        """
        if not self._last_ruleset:
            logger.warning("No saved state available for rollback")
            return False

        try:
            self._exec_nft_script(self._last_ruleset)
            logger.info("Rolled back to previous state")
            return True
        except NftablesError as e:
            logger.error("Rollback failed: %s", e)
            return False

    def _save_current_state(self) -> None:
        """Save the current nftables ruleset for rollback."""
        try:
            result = self._exec_nft("list", "ruleset", check=False)
            if result.returncode == 0:
                self._last_ruleset = result.stdout
        except NftablesError:
            self._last_ruleset = None

    # ─── Status & Inspection ─────────────────────────────────────────

    def get_current_ruleset(self) -> str:
        """Get the current nftables ruleset as text."""
        if self.demo_mode:
            return "(demo mode — no live ruleset)"
        result = self._exec_nft("list", "ruleset")
        return result.stdout

    def get_current_ruleset_json(self) -> dict:
        """Get the current nftables ruleset as JSON."""
        if self.demo_mode:
            return {"nftables": []}
        result = self._exec_nft("-j", "list", "ruleset")
        return json.loads(result.stdout)

    def get_rule_counters(self) -> dict[str, int]:
        """
        Get packet counters for Bastion rules.

        Returns a mapping of rule_id -> hit_count by parsing nft comments.
        """
        if self.demo_mode:
            return {}

        try:
            result = self._exec_nft("-j", "list", "table", "inet", self.BASTION_TABLE)
            data = json.loads(result.stdout)

            counters: dict[str, int] = {}
            for item in data.get("nftables", []):
                rule = item.get("rule", {})
                comment = rule.get("comment", "")
                if comment.startswith("bastion:"):
                    rule_id = comment.split(":", 1)[1]
                    expr = rule.get("expr", [])
                    for e in expr:
                        if "counter" in e:
                            counters[rule_id] = e["counter"].get("packets", 0)
            return counters
        except (NftablesError, json.JSONDecodeError):
            return {}

    def is_available(self) -> bool:
        """Check if nftables is available on the system."""
        if self.demo_mode:
            return True
        try:
            result = self._exec_nft("--version", check=False)
            return result.returncode == 0
        except NftablesError:
            return False
