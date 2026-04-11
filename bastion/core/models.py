"""
Bastion Firewall Models

Defines the core data structures for firewall rules, chains, and tables.
All models are backend-agnostic and serialize to/from YAML and JSON.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Action(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    RATE_LIMIT = "rate_limit"
    JUMP = "jump"


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    FORWARD = "forward"


class RuleState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    PENDING = "pending"
    ERROR = "error"


class IPVersion(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    BOTH = "both"


@dataclass
class PortRange:
    """Represents a port or port range (e.g., 80, 1024-65535)."""

    start: int
    end: int | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.start <= 65535:
            raise ValueError(f"Port start must be 0-65535, got {self.start}")
        if self.end is not None:
            if not 0 <= self.end <= 65535:
                raise ValueError(f"Port end must be 0-65535, got {self.end}")
            if self.end < self.start:
                raise ValueError(f"Port end ({self.end}) must be >= start ({self.start})")

    def to_nft(self) -> str:
        """Convert to nftables port expression."""
        if self.end is None or self.end == self.start:
            return str(self.start)
        return f"{self.start}-{self.end}"

    @classmethod
    def from_string(cls, s: str) -> PortRange:
        """Parse from string like '80' or '1024-65535'."""
        if "-" in s:
            start, end = s.split("-", 1)
            return cls(start=int(start.strip()), end=int(end.strip()))
        return cls(start=int(s.strip()))


@dataclass
class RateLimit:
    """Rate limiting configuration."""

    rate: int  # packets per period
    period: str = "second"  # second, minute, hour
    burst: int = 5

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("Rate limit rate must be greater than 0")
        if self.period not in {"second", "minute", "hour"}:
            raise ValueError("Rate limit period must be one of: second, minute, hour")
        if self.burst < 0:
            raise ValueError("Rate limit burst must be 0 or greater")

    def to_nft(self) -> str:
        return f"limit rate {self.rate}/{self.period} burst {self.burst} packets"


@dataclass
class FirewallRule:
    """
    A single firewall rule.

    Rules are the fundamental building block of Bastion's firewall engine.
    Each rule defines a match condition and an action to take on matching packets.
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

    # Match conditions
    direction: Direction = Direction.INBOUND
    protocol: Protocol = Protocol.ANY
    ip_version: IPVersion = IPVersion.BOTH

    source_address: str | None = None  # CIDR notation: 192.168.1.0/24
    destination_address: str | None = None
    source_port: PortRange | None = None
    destination_port: PortRange | None = None
    interface_in: str | None = None  # e.g., eth0
    interface_out: str | None = None

    # Action
    action: Action = Action.DROP
    jump_target: str | None = None  # chain name if action is JUMP
    rate_limit: RateLimit | None = None  # config if action is RATE_LIMIT
    log_prefix: str | None = None  # log prefix if action is LOG

    # Metadata
    priority: int = 100  # lower = evaluated first
    state: RuleState = RuleState.ENABLED
    hit_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    group: str | None = None

    def validate(self) -> list[str]:
        """
        Validate the rule and return a list of error messages.
        Returns an empty list if the rule is valid.
        """
        errors: list[str] = []

        if self.action == Action.JUMP and not self.jump_target:
            errors.append("JUMP action requires a jump_target chain name")

        if self.action == Action.RATE_LIMIT and not self.rate_limit:
            errors.append("RATE_LIMIT action requires rate_limit configuration")

        if self.protocol == Protocol.ICMP:
            if self.source_port or self.destination_port:
                errors.append("ICMP protocol does not support port specifications")
        elif self.protocol == Protocol.ANY and (self.source_port or self.destination_port):
            errors.append("Port specifications require protocol tcp or udp")

        if self.source_address:
            errors.extend(self._validate_cidr(self.source_address, "source_address"))

        if self.destination_address:
            errors.extend(self._validate_cidr(self.destination_address, "destination_address"))

        # interface_in, interface_out, log_prefix, and jump_target are
        # interpolated into the generated nft script.  They MUST contain
        # only safe characters — no quotes, semicolons, newlines, or
        # shell metacharacters — to prevent nft command injection.
        safe_ident = re.compile(r"^[a-zA-Z0-9._\-]+$")
        safe_prefix = re.compile(r"^[a-zA-Z0-9._\-: ]+$")

        if self.interface_in:
            if len(self.interface_in) > 64:
                errors.append("interface_in must be 64 characters or fewer")
            if not safe_ident.match(self.interface_in):
                errors.append("interface_in contains invalid characters")

        if self.interface_out:
            if len(self.interface_out) > 64:
                errors.append("interface_out must be 64 characters or fewer")
            if not safe_ident.match(self.interface_out):
                errors.append("interface_out contains invalid characters")

        if self.log_prefix:
            if len(self.log_prefix) > 64:
                errors.append("log_prefix must be 64 characters or fewer")
            if not safe_prefix.match(self.log_prefix):
                errors.append("log_prefix contains invalid characters")

        if self.jump_target and not safe_ident.match(self.jump_target):
            errors.append("jump_target contains invalid characters")

        if self.priority < 0 or self.priority > 10000:
            errors.append("Priority must be between 0 and 10000")

        return errors

    @staticmethod
    def _validate_cidr(cidr: str, field_name: str) -> list[str]:
        """Validate a CIDR notation address."""
        errors: list[str] = []
        try:
            if "/" in cidr:
                ipaddress.ip_network(cidr, strict=False)
            else:
                ipaddress.ip_address(cidr)
        except ValueError as exc:
            errors.append(f"{field_name}: {exc}")
        return errors

    def to_dict(self) -> dict[str, object]:
        """Serialize to dictionary for JSON/YAML export."""
        d: dict[str, object] = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "direction": self.direction.value,
            "protocol": self.protocol.value,
            "ip_version": self.ip_version.value,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "source_port": self.source_port.to_nft() if self.source_port else None,
            "destination_port": self.destination_port.to_nft() if self.destination_port else None,
            "interface_in": self.interface_in,
            "interface_out": self.interface_out,
            "action": self.action.value,
            "jump_target": self.jump_target,
            "log_prefix": self.log_prefix,
            "priority": self.priority,
            "state": self.state.value,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "group": self.group,
        }
        if self.rate_limit:
            d["rate_limit"] = {
                "rate": self.rate_limit.rate,
                "period": self.rate_limit.period,
                "burst": self.rate_limit.burst,
            }
        return d


@dataclass
class Chain:
    """An nftables chain containing ordered rules."""

    name: str
    table: str = "bastion"
    chain_type: str = "filter"  # filter, nat, route
    hook: str | None = None  # input, output, forward, prerouting, postrouting
    priority: int = 0
    policy: Action = Action.DROP
    rules: list[FirewallRule] = field(default_factory=list)

    def get_sorted_rules(self) -> list[FirewallRule]:
        """Return rules sorted by priority (lowest first)."""
        return sorted(self.rules, key=lambda r: r.priority)

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a rule with validation."""
        errors = rule.validate()
        if errors:
            raise ValueError(f"Invalid rule: {'; '.join(errors)}")
        self.rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found and removed."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False


@dataclass
class Table:
    """An nftables table containing chains."""

    name: str = "bastion"
    family: str = "inet"  # inet (dual-stack), ip, ip6
    chains: dict[str, Chain] = field(default_factory=dict)

    def add_chain(self, chain: Chain) -> None:
        self.chains[chain.name] = chain

    def get_chain(self, name: str) -> Chain | None:
        return self.chains.get(name)


@dataclass
class RuleSet:
    """
    The complete firewall ruleset.
    This is the top-level object that gets serialized to/from configuration.
    """

    tables: dict[str, Table] = field(default_factory=dict)
    version: str = "1"
    last_applied: datetime | None = None

    def add_table(self, table: Table) -> None:
        self.tables[table.name] = table

    def get_all_rules(self) -> list[FirewallRule]:
        """Flatten all rules from all tables and chains."""
        rules: list[FirewallRule] = []
        for table in self.tables.values():
            for chain in table.chains.values():
                rules.extend(chain.rules)
        return rules

    def find_rule(self, rule_id: str) -> FirewallRule | None:
        """Find a rule by ID across all tables and chains."""
        for rule in self.get_all_rules():
            if rule.id == rule_id:
                return rule
        return None

    def get_conflicts(self) -> list[tuple[FirewallRule, FirewallRule, str]]:
        """
        Detect potentially conflicting rules.
        Returns list of (rule_a, rule_b, reason) tuples.
        """
        conflicts: list[tuple[FirewallRule, FirewallRule, str]] = []
        all_rules = self.get_all_rules()

        for i, rule_a in enumerate(all_rules):
            for rule_b in all_rules[i + 1 :]:
                if rule_a.state != RuleState.ENABLED or rule_b.state != RuleState.ENABLED:
                    continue

                # Same direction, protocol, and overlapping addresses but different actions
                if (
                    rule_a.direction == rule_b.direction
                    and rule_a.protocol == rule_b.protocol
                    and rule_a.action != rule_b.action
                    and rule_a.source_address == rule_b.source_address
                    and rule_a.destination_address == rule_b.destination_address
                    and rule_a.destination_port == rule_b.destination_port
                ):
                    conflicts.append(
                        (rule_a, rule_b, "Overlapping match criteria with different actions")
                    )

        return conflicts
