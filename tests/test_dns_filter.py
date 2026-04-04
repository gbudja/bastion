"""Tests for the Bastion DNS filtering plugin."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from bastion.plugins.dns_filter import (
    BlocklistManager,
    Plugin,
    build_sinkhole_response,
    parse_dns_query,
)


def make_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Create a minimal DNS query packet for tests."""
    labels = domain.rstrip(".").split(".")
    question = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in labels)
    question += b"\x00" + struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + question


class TestBlocklistManager:
    def test_load_plain_and_hosts_entries(self):
        manager = BlocklistManager()
        count = manager.load_from_lines(
            [
                "example.com",
                "0.0.0.0 ads.example.net",
                "127.0.0.1 localhost",
                "bad line",
            ]
        )
        assert count == 2
        assert manager.is_blocked("example.com") is True
        assert manager.is_blocked("sub.ads.example.net") is True

    def test_allowlist_overrides_parent_block(self):
        manager = BlocklistManager()
        manager.load_from_lines(["example.com"])
        manager.add_allowlist_entry("safe.example.com")
        assert manager.is_blocked("safe.example.com") is False
        assert manager.is_blocked("ads.example.com") is True

    def test_reject_non_http_blocklist_urls(self):
        manager = BlocklistManager()
        assert manager.load_from_url("file:///tmp/blocklist.txt") == 0


class TestDnsProtocol:
    def test_parse_dns_query(self):
        packet = make_dns_query("ads.example.com")
        question = parse_dns_query(packet)
        assert question.transaction_id == 0x1234
        assert question.qname == "ads.example.com"
        assert question.qtype == 1

    def test_parse_rejects_truncated_packets(self):
        with pytest.raises(ValueError):
            parse_dns_query(b"\x00\x01")

    def test_build_sinkhole_response(self):
        packet = make_dns_query("ads.example.com")
        response = build_sinkhole_response(packet, sinkhole_ip="127.0.0.1")
        assert response[:2] == b"\x12\x34"
        assert response[-4:] == b"\x7f\x00\x00\x01"


class TestPlugin:
    def test_plugin_enable_query_and_sinkhole(self):
        blocklist = Path("tests") / "_dns_filter_blocklist.txt"
        blocklist.write_text("ads.example.com\n", encoding="utf-8")
        plugin = Plugin()
        try:
            plugin.on_enable(
                {
                    "blocklists": [str(blocklist)],
                    "allowlist": ["safe.ads.example.com"],
                    "sinkhole_ip": "127.0.0.1",
                }
            )

            assert plugin.should_block("ads.example.com") is True
            assert plugin.should_block("safe.ads.example.com") is False

            packet = make_dns_query("ads.example.com")
            response = plugin.handle_dns_query(packet)
            assert response is not None
            assert response[-4:] == b"\x7f\x00\x00\x01"
        finally:
            blocklist.unlink(missing_ok=True)

    def test_plugin_api_routes_validate_domain(self):
        plugin = Plugin()
        plugin.on_enable({"allowlist": [], "blocklists": []})
        with pytest.raises(ValueError):
            plugin.api_query({})
