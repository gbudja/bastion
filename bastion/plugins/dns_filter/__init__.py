"""
Bastion DNS filtering plugin.

Provides blocklist management, simple DNS question parsing, and
sinkhole response generation suitable for demo mode and API-level tests.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bastion import __version__
from bastion.plugins import BastionPlugin, PluginMeta
from bastion.plugins.dns_filter.blocklist import BlocklistManager


@dataclass(frozen=True)
class DNSQuestion:
    """A parsed DNS question."""

    transaction_id: int
    qname: str
    qtype: int
    qclass: int


def parse_dns_query(packet: bytes) -> DNSQuestion:
    """Parse a minimal DNS query packet and return its first question."""
    if len(packet) < 12:
        raise ValueError("DNS packet is too short")

    transaction_id, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if qdcount != 1:
        raise ValueError("Only single-question DNS packets are supported")

    labels: list[str] = []
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("DNS question is truncated")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("Compressed DNS questions are not supported")
        label_end = offset + length
        if label_end > len(packet):
            raise ValueError("DNS label exceeds packet size")
        labels.append(packet[offset:label_end].decode("ascii"))
        offset = label_end

    if offset + 4 > len(packet):
        raise ValueError("DNS question is missing qtype/qclass")

    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return DNSQuestion(
        transaction_id=transaction_id,
        qname=".".join(labels).lower(),
        qtype=qtype,
        qclass=qclass,
    )


def build_sinkhole_response(packet: bytes, sinkhole_ip: str = "0.0.0.0") -> bytes:
    """Build a minimal A-record sinkhole response for a parsed DNS query."""
    question = parse_dns_query(packet)
    address = ipaddress.ip_address(sinkhole_ip)
    if address.version != 4:
        raise ValueError("Only IPv4 sinkhole responses are currently supported")

    question_end = _question_end_offset(packet)
    header = struct.pack(
        "!HHHHHH",
        question.transaction_id,
        0x8180,
        1,
        1,
        0,
        0,
    )
    answer = b"".join(
        [
            b"\xc0\x0c",
            struct.pack("!H", 1),
            struct.pack("!H", question.qclass),
            struct.pack("!I", 60),
            struct.pack("!H", 4),
            address.packed,
        ]
    )
    return header + packet[12:question_end] + answer


def _question_end_offset(packet: bytes) -> int:
    """Return the byte offset immediately after the first DNS question."""
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("DNS question is truncated")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("Compressed DNS questions are not supported")
        offset += length
    return offset + 4


class Plugin(BastionPlugin):
    """DNS filtering plugin implementation."""

    def __init__(self) -> None:
        self.blocklist = BlocklistManager()
        self.enabled = False
        self.sinkhole_ip = "0.0.0.0"

    def get_meta(self) -> PluginMeta:
        return PluginMeta(
            name="DNS Filter",
            version=__version__,
            description="Domain blocklist filtering with allowlist overrides",
            author="Bastion Contributors",
            config_schema={
                "blocklists": ["list[str]"],
                "allowlist": ["list[str]"],
                "sinkhole_ip": "IPv4 address",
            },
        )

    def on_enable(self, config: dict[str, Any]) -> None:
        self.blocklist.clear()

        for source in config.get("blocklists", []):
            path = Path(source)
            if path.exists():
                self.blocklist.load_from_file(path)
            else:
                self.blocklist.load_from_url(str(source))

        allowlist = config.get("allowlist", [])
        if allowlist:
            self.blocklist.load_allowlist_from_lines([str(item) for item in allowlist])

        self.sinkhole_ip = str(config.get("sinkhole_ip", "0.0.0.0"))
        ipaddress.ip_address(self.sinkhole_ip)
        self.enabled = True

    def on_disable(self) -> None:
        self.enabled = False

    def get_api_routes(self) -> list[dict[str, Any]]:
        return [
            {
                "method": "GET",
                "path": "status",
                "handler": self.api_status,
                "description": "Return DNS filter plugin status",
            },
            {
                "method": "POST",
                "path": "query",
                "handler": self.api_query,
                "description": "Check whether a domain would be blocked",
            },
        ]

    def api_status(self, _payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return current plugin status information."""
        return {
            "enabled": self.enabled,
            "blocked_count": self.blocklist.blocked_count,
            "allowed_count": self.blocklist.allowed_count,
            "sources": self.blocklist.sources,
            "sinkhole_ip": self.sinkhole_ip,
        }

    def api_query(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Check whether a domain is blocked."""
        domain = str((payload or {}).get("domain", "")).strip().lower().rstrip(".")
        if not domain:
            raise ValueError("domain is required")
        return {"domain": domain, "blocked": self.should_block(domain)}

    def should_block(self, domain: str) -> bool:
        """Return True when a DNS query should be blocked."""
        return self.enabled and self.blocklist.is_blocked(domain)

    def handle_dns_query(self, packet: bytes) -> bytes | None:
        """Return a sinkhole response when the query should be blocked."""
        question = parse_dns_query(packet)
        if not self.should_block(question.qname):
            return None
        return build_sinkhole_response(packet, sinkhole_ip=self.sinkhole_ip)


__all__ = [
    "BlocklistManager",
    "DNSQuestion",
    "Plugin",
    "build_sinkhole_response",
    "parse_dns_query",
]
