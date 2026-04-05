"""
Bastion Network Monitor

Collects real-time system and network metrics including CPU, memory,
disk, interface statistics, connection tracking, and host discovery.

In demo mode all collection methods return deterministic simulated data
so the monitor works correctly in Docker containers and on non-Linux
systems where psutil operations may fail or require elevated privileges.
"""

from __future__ import annotations

import logging
import math
import socket
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


@dataclass
class SessionInfo:
    """A normalized active network session for UI/API consumption."""

    source_ip: str
    destination: str
    protocol: str
    duration: float
    status: str
    pid: int | None = None


class NetworkMonitor:
    """
    Real-time network and system monitoring engine.

    Collects periodic snapshots of system resources, network interfaces,
    and connection tracking data. Maintains a rolling history for
    time-series display in the dashboard.

    When demo_mode=True all methods return simulated data — no psutil
    calls are made, so the monitor works in unprivileged containers and
    on Windows or macOS development machines.
    """

    def __init__(self, interval: int = 5, demo_mode: bool = False) -> None:
        """
        Args:
            interval: Seconds between metric collection cycles.
            demo_mode: If True, return simulated data instead of calling psutil.
        """
        self.interval = interval
        self.demo_mode = demo_mode

        # Rolling metric history
        self.system_history: deque[SystemStats] = deque(maxlen=MAX_HISTORY)
        self.network_history: deque[NetworkSnapshot] = deque(maxlen=MAX_HISTORY)

        # Host tracking
        self.hosts: dict[str, TrackedHost] = {}

        # Last snapshot for rate calculation (live mode only)
        self._last_net_counters: dict[str, Any] | None = None
        self._last_net_time: float | None = None

        # Demo mode: stable base time so simulation curves are consistent
        self._demo_start: float = time.time()
        self._session_started_at: dict[str, float] = {}

    # ─── Demo helpers ────────────────────────────────────────────────

    def _demo_system_stats(self) -> SystemStats:
        """Return smoothly varying simulated system stats."""
        t = time.time() - self._demo_start
        cpu = 15.0 + math.sin(t / 20.0) * 10.0 + (math.sin(t * 3.7) * 3.0)
        mem_pct = 38.0 + math.sin(t / 60.0) * 5.0
        disk_pct = min(42.0 + t * 0.001, 95.0)
        mem_total = 8 * 1024**3
        return SystemStats(
            timestamp=time.time(),
            cpu_percent=max(1.0, min(99.0, cpu)),
            cpu_count=4,
            memory_total=mem_total,
            memory_used=int(mem_total * mem_pct / 100),
            memory_percent=mem_pct,
            disk_total=100 * 1024**3,
            disk_used=int(100 * 1024**3 * disk_pct / 100),
            disk_percent=disk_pct,
            load_avg=(max(0.0, 0.5 + math.sin(t / 30)), 0.4, 0.3),
            uptime=t + 3600 * 26,  # simulate 26 h uptime at start
        )

    def _demo_network_snapshot(self) -> NetworkSnapshot:
        """Return smoothly varying simulated network snapshot."""
        t = time.time() - self._demo_start
        base_in = 45000.0 + math.sin(t / 30.0) * 20000.0
        base_out = 12000.0 + math.sin(t / 25.0) * 8000.0
        bps_in = max(0.0, base_in + math.sin(t * 5.1) * 5000.0)
        bps_out = max(0.0, base_out + math.sin(t * 4.3) * 3000.0)
        sessions = max(0, int(80 + math.sin(t / 15.0) * 30))
        eth0 = InterfaceStats(
            name="eth0",
            bytes_sent=int(1e9 + bps_out * t),
            bytes_recv=int(4e9 + bps_in * t),
            packets_sent=int(1e6),
            packets_recv=int(4e6),
            errors_in=0,
            errors_out=0,
            drops_in=0,
            drops_out=0,
            speed_mbps=1000,
            is_up=True,
            addresses=[{"family": "AF_INET", "address": "172.17.0.2", "netmask": "255.255.0.0"}],
        )
        return NetworkSnapshot(
            timestamp=time.time(),
            interfaces={"eth0": eth0},
            total_bytes_sent=eth0.bytes_sent,
            total_bytes_recv=eth0.bytes_recv,
            total_connections=sessions + 60,
            active_sessions=sessions,
            bytes_per_sec_in=bps_in,
            bytes_per_sec_out=bps_out,
        )

    # ─── System Metrics ──────────────────────────────────────────────

    def collect_system_stats(self) -> SystemStats:
        """Collect current system resource usage."""
        if self.demo_mode:
            stats = self._demo_system_stats()
            self.system_history.append(stats)
            return stats

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
        if self.demo_mode:
            snapshot = self._demo_network_snapshot()
            self.network_history.append(snapshot)
            return snapshot

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

        # psutil.net_connections requires elevated privileges on some systems.
        # Catch AccessDenied and return zero counts rather than crashing.
        try:
            connections = psutil.net_connections(kind="inet")
            active_sessions = len([c for c in connections if c.status == "ESTABLISHED"])
            total_connections = len(connections)
        except (psutil.AccessDenied, PermissionError):
            logger.debug("net_connections: access denied, reporting zero connections")
            connections = []
            active_sessions = 0
            total_connections = 0

        snapshot = NetworkSnapshot(
            timestamp=now,
            interfaces=interfaces,
            total_bytes_sent=total_sent,
            total_bytes_recv=total_recv,
            total_connections=total_connections,
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

        In demo mode returns a small static list of placeholder hosts so the
        dashboard hosts panel shows data without requiring /proc access.
        """
        if self.demo_mode:
            now = time.time()
            return [
                TrackedHost(
                    ip_address="192.168.1.1",
                    mac_address="aa:bb:cc:dd:ee:01",
                    hostname="gateway.local",
                    first_seen=now - 3600,
                    last_seen=now,
                    active_connections=3,
                ),
                TrackedHost(
                    ip_address="192.168.1.100",
                    mac_address="aa:bb:cc:dd:ee:02",
                    hostname="workstation.local",
                    first_seen=now - 1800,
                    last_seen=now - 30,
                    active_connections=1,
                ),
            ]

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

    # ─── Session Tracking ───────────────────────────────────────────

    @staticmethod
    def _connection_protocol(sock_type: int) -> str:
        """Return a protocol label for a socket type."""
        if sock_type == socket.SOCK_STREAM:
            return "tcp"
        if sock_type == socket.SOCK_DGRAM:
            return "udp"
        return "unknown"

    @staticmethod
    def _connection_key(conn: Any) -> str:
        """Build a stable key for tracking session first-seen times."""
        local = f"{getattr(conn.laddr, 'ip', '')}:{getattr(conn.laddr, 'port', '')}"
        remote = f"{getattr(conn.raddr, 'ip', '')}:{getattr(conn.raddr, 'port', '')}"
        return f"{conn.pid}:{conn.type}:{local}:{remote}"

    def _demo_sessions(self) -> list[SessionInfo]:
        """Return stable simulated sessions for demo environments."""
        t = time.time() - self._demo_start
        durations = [
            42 + int(t % 30),
            185 + int((t * 1.3) % 60),
            960 + int((t * 0.8) % 120),
        ]
        return [
            SessionInfo(
                source_ip="203.0.113.14",
                destination="172.17.0.2:443",
                protocol="tcp",
                duration=durations[0],
                status="ESTABLISHED",
                pid=412,
            ),
            SessionInfo(
                source_ip="198.51.100.24",
                destination="172.17.0.2:22",
                protocol="tcp",
                duration=durations[1],
                status="ESTABLISHED",
                pid=184,
            ),
            SessionInfo(
                source_ip="192.0.2.53",
                destination="172.17.0.2:53",
                protocol="udp",
                duration=durations[2],
                status="ESTABLISHED",
                pid=None,
            ),
        ]

    def get_active_sessions(self, limit: int = 200) -> list[SessionInfo]:
        """
        Return normalized active sessions with protocol and observed duration.

        Duration is "time since Bastion first observed the connection", not a
        kernel-reported TCP age. This keeps the API honest while still giving
        operators useful relative longevity data.
        """
        if self.demo_mode:
            return self._demo_sessions()[:limit]

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("net_connections: access denied, reporting zero sessions")
            self._session_started_at.clear()
            return []

        now = time.time()
        active_keys: set[str] = set()
        sessions: list[SessionInfo] = []

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue

            key = self._connection_key(conn)
            active_keys.add(key)
            started_at = self._session_started_at.setdefault(key, now)

            sessions.append(
                SessionInfo(
                    source_ip=conn.raddr.ip,
                    destination=f"{conn.laddr.ip}:{conn.laddr.port}",
                    protocol=self._connection_protocol(conn.type),
                    duration=max(0.0, now - started_at),
                    status=conn.status,
                    pid=conn.pid,
                )
            )

        self._session_started_at = {
            key: started for key, started in self._session_started_at.items() if key in active_keys
        }

        sessions.sort(key=lambda session: session.duration, reverse=True)
        return sessions[:limit]

    # ─── Aggregated Dashboard Data ───────────────────────────────────

    def get_dashboard_data(self) -> dict:
        """
        Collect all metrics for the dashboard in a single call.

        Returns a dict suitable for JSON serialization and WebSocket push.
        In demo mode, all data is simulated — no system calls are made.
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
