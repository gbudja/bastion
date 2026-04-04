"""
Bastion Network Monitor

Collects real-time system and network metrics including CPU, memory,
disk, interface statistics, connection tracking, and host discovery.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger(__name__)

# Max data points retained in memory (at 5s intervals, ~1 hour of data)
MAX_HISTORY = 720


@dataclass
class InterfaceStats:
    """Network interface statistics snapshot."""

    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int
    drops_in: int
    drops_out: int
    speed_mbps: int | None = None
    is_up: bool = True
    addresses: list[dict] = field(default_factory=list)


@dataclass
class SystemStats:
    """System resource usage snapshot."""

    timestamp: float
    cpu_percent: float
    cpu_count: int
    memory_total: int  # bytes
    memory_used: int
    memory_percent: float
    disk_total: int
    disk_used: int
    disk_percent: float
    load_avg: tuple[float, float, float]
    uptime: float  # seconds


@dataclass
class NetworkSnapshot:
    """Complete network state at a point in time."""

    timestamp: float
    interfaces: dict[str, InterfaceStats]
    total_bytes_sent: int
    total_bytes_recv: int
    total_connections: int
    active_sessions: int
    bytes_per_sec_in: float = 0.0
    bytes_per_sec_out: float = 0.0


@dataclass
class TrackedHost:
    """A discovered host on the network."""

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_recv: int = 0
    active_connections: int = 0


class NetworkMonitor:
    """
    Real-time network and system monitoring engine.

    Collects periodic snapshots of system resources, network interfaces,
    and connection tracking data. Maintains a rolling history for
    time-series display in the dashboard.
    """

    def __init__(self, interval: int = 5, demo_mode: bool = False) -> None:
        """
        Args:
            interval: Seconds between metric collection cycles.
            demo_mode: If True, generate simulated data.
        """
        self.interval = interval
        self.demo_mode = demo_mode

        # Rolling metric history
        self.system_history: deque[SystemStats] = deque(maxlen=MAX_HISTORY)
        self.network_history: deque[NetworkSnapshot] = deque(maxlen=MAX_HISTORY)

        # Host tracking
        self.hosts: dict[str, TrackedHost] = {}

        # Last snapshot for rate calculation
        self._last_net_counters: dict[str, Any] | None = None
        self._last_net_time: float | None = None

    # ─── System Metrics ──────────────────────────────────────────────

    def collect_system_stats(self) -> SystemStats:
        """Collect current system resource usage."""
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        stats = SystemStats(
            timestamp=time.time(),
            cpu_percent=psutil.cpu_percent(interval=0.1),
            cpu_count=psutil.cpu_count() or 1,
            memory_total=mem.total,
            memory_used=mem.used,
            memory_percent=mem.percent,
            disk_total=disk.total,
            disk_used=disk.used,
            disk_percent=disk.percent,
            load_avg=psutil.getloadavg(),
            uptime=time.time() - psutil.boot_time(),
        )

        self.system_history.append(stats)
        return stats

    # ─── Network Metrics ─────────────────────────────────────────────

    def collect_network_stats(self) -> NetworkSnapshot:
        """Collect current network interface and connection statistics."""
        now = time.time()

        # Interface counters
        net_io = psutil.net_io_counters(pernic=True)
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        interfaces: dict[str, InterfaceStats] = {}
        total_sent = 0
        total_recv = 0

        for name, counters in net_io.items():
            if_stat = net_if_stats.get(name)
            addrs = []
            for addr in net_if_addrs.get(name, []):
                addrs.append(
                    {
                        "family": str(addr.family.name),
                        "address": addr.address,
                        "netmask": addr.netmask,
                    }
                )

            interfaces[name] = InterfaceStats(
                name=name,
                bytes_sent=counters.bytes_sent,
                bytes_recv=counters.bytes_recv,
                packets_sent=counters.packets_sent,
                packets_recv=counters.packets_recv,
                errors_in=counters.errin,
                errors_out=counters.errout,
                drops_in=counters.dropin,
                drops_out=counters.dropout,
                speed_mbps=if_stat.speed if if_stat else None,
                is_up=if_stat.isup if if_stat else False,
                addresses=addrs,
            )
            total_sent += counters.bytes_sent
            total_recv += counters.bytes_recv

        # Calculate throughput rate
        bps_in = 0.0
        bps_out = 0.0
        if self._last_net_counters and self._last_net_time:
            elapsed = now - self._last_net_time
            if elapsed > 0:
                prev_sent = sum(c.bytes_sent for c in self._last_net_counters.values())
                prev_recv = sum(c.bytes_recv for c in self._last_net_counters.values())
                bps_out = (total_sent - prev_sent) / elapsed
                bps_in = (total_recv - prev_recv) / elapsed

        self._last_net_counters = net_io
        self._last_net_time = now

        # Connection tracking
        connections = psutil.net_connections(kind="inet")
        active_sessions = len([c for c in connections if c.status == "ESTABLISHED"])

        snapshot = NetworkSnapshot(
            timestamp=now,
            interfaces=interfaces,
            total_bytes_sent=total_sent,
            total_bytes_recv=total_recv,
            total_connections=len(connections),
            active_sessions=active_sessions,
            bytes_per_sec_in=bps_in,
            bytes_per_sec_out=bps_out,
        )

        self.network_history.append(snapshot)
        return snapshot

    # ─── Host Discovery ──────────────────────────────────────────────

    def discover_hosts(self) -> list[TrackedHost]:
        """
        Discover active hosts by examining the ARP table and active connections.
        """
        now = time.time()

        # Parse ARP table
        arp_path = Path("/proc/net/arp")
        if arp_path.exists():
            try:
                lines = arp_path.read_text().strip().split("\n")[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            if ip in self.hosts:
                                self.hosts[ip].last_seen = now
                                self.hosts[ip].mac_address = mac
                            else:
                                self.hosts[ip] = TrackedHost(
                                    ip_address=ip,
                                    mac_address=mac,
                                    first_seen=now,
                                    last_seen=now,
                                )
            except (PermissionError, OSError) as e:
                logger.debug("Could not read ARP table: %s", e)

        # Enrich from active connections
        try:
            connections = psutil.net_connections(kind="inet")
            connection_count: dict[str, int] = {}
            for conn in connections:
                if conn.raddr:
                    ip = conn.raddr.ip
                    connection_count[ip] = connection_count.get(ip, 0) + 1

            for ip, count in connection_count.items():
                if ip in self.hosts:
                    self.hosts[ip].active_connections = count
                    self.hosts[ip].last_seen = now
        except (PermissionError, psutil.AccessDenied):
            pass

        return list(self.hosts.values())

    # ─── Aggregated Dashboard Data ───────────────────────────────────

    def get_dashboard_data(self) -> dict:
        """
        Collect all metrics for the dashboard in a single call.

        Returns a dict suitable for JSON serialization and WebSocket push.
        """
        system = self.collect_system_stats()
        network = self.collect_network_stats()
        hosts = self.discover_hosts()

        return {
            "timestamp": time.time(),
            "system": {
                "cpu_percent": system.cpu_percent,
                "cpu_count": system.cpu_count,
                "memory_total": system.memory_total,
                "memory_used": system.memory_used,
                "memory_percent": system.memory_percent,
                "disk_total": system.disk_total,
                "disk_used": system.disk_used,
                "disk_percent": system.disk_percent,
                "load_avg": list(system.load_avg),
                "uptime": system.uptime,
            },
            "network": {
                "bytes_per_sec_in": network.bytes_per_sec_in,
                "bytes_per_sec_out": network.bytes_per_sec_out,
                "total_connections": network.total_connections,
                "active_sessions": network.active_sessions,
                "interfaces": {
                    name: {
                        "bytes_sent": iface.bytes_sent,
                        "bytes_recv": iface.bytes_recv,
                        "is_up": iface.is_up,
                        "speed_mbps": iface.speed_mbps,
                    }
                    for name, iface in network.interfaces.items()
                },
            },
            "hosts": {
                "total": len(hosts),
                "active": len([h for h in hosts if time.time() - h.last_seen < 300]),
                "list": [
                    {
                        "ip": h.ip_address,
                        "mac": h.mac_address,
                        "hostname": h.hostname,
                        "last_seen": h.last_seen,
                        "connections": h.active_connections,
                    }
                    for h in sorted(hosts, key=lambda h: h.last_seen, reverse=True)[:50]
                ],
            },
            "history": {
                "cpu": [
                    {"t": s.timestamp, "v": s.cpu_percent} for s in list(self.system_history)[-60:]
                ],
                "memory": [
                    {"t": s.timestamp, "v": s.memory_percent}
                    for s in list(self.system_history)[-60:]
                ],
                "throughput_in": [
                    {"t": n.timestamp, "v": n.bytes_per_sec_in}
                    for n in list(self.network_history)[-60:]
                ],
                "throughput_out": [
                    {"t": n.timestamp, "v": n.bytes_per_sec_out}
                    for n in list(self.network_history)[-60:]
                ],
            },
        }
