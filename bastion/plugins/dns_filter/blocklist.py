"""
Bastion DNS Filter — Blocklist Manager

Handles loading, caching, and querying domain blocklists from multiple
sources: local files, hosts-format files, and remote URLs.
"""

from __future__ import annotations

import logging
import re
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Regex matching a valid domain label component
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# Maximum number of bytes to read from a remote blocklist (10 MB).
_MAX_BLOCKLIST_BYTES = 10 * 1024 * 1024


def _is_valid_domain(domain: str) -> bool:
    """Return True if *domain* looks like a well-formed hostname."""
    return bool(_DOMAIN_RE.match(domain))


class BlocklistManager:
    """
    Manages one or more domain blocklists.

    Supports:
    - Plain-text lists (one domain per line)
    - Hosts-format files (``0.0.0.0 example.com`` or ``127.0.0.1 example.com``)
    - Remote URLs (fetched once at load time)

    Allowlist entries always override blocklist entries.
    """

    def __init__(self) -> None:
        self._blocked: set[str] = set()
        self._allowed: set[str] = set()
        self._sources: list[str] = []

    # ─── Loading ─────────────────────────────────────────────────────

    def load_from_file(self, path: Path) -> int:
        """
        Load domains from a local file.

        Accepts both plain domain lists and hosts-format files.
        Returns the number of domains added.
        """
        if not path.exists():
            logger.warning("Blocklist file not found: %s", path)
            return 0

        added = 0
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            added = self._parse_and_add(text)
            self._sources.append(str(path))
            logger.info("Loaded %d domains from %s", added, path)
        except OSError as e:
            logger.error("Failed to read blocklist %s: %s", path, e)
        return added

    def load_from_url(self, url: str, timeout: int = 15) -> int:
        """
        Fetch and load a blocklist from a remote HTTPS URL.

        Only ``https://`` is accepted — plain HTTP is rejected to prevent
        a compromised network from injecting malicious blocklist entries.
        Responses larger than ``_MAX_BLOCKLIST_BYTES`` (10 MB) are rejected.

        Returns the number of domains added, or 0 on error.
        """
        parsed = urlparse(url)
        # Security: reject plain HTTP to prevent MITM blocklist injection.
        if parsed.scheme != "https":
            logger.error(
                "Rejected blocklist URL with non-HTTPS scheme (%s): %s",
                parsed.scheme,
                url,
            )
            return 0
        try:
            ssl_ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                url, timeout=timeout, context=ssl_ctx
            ) as resp:  # noqa: S310
                raw = resp.read(_MAX_BLOCKLIST_BYTES + 1)
                if len(raw) > _MAX_BLOCKLIST_BYTES:
                    logger.error(
                        "Blocklist at %s exceeds %d byte limit — rejected",
                        url,
                        _MAX_BLOCKLIST_BYTES,
                    )
                    return 0
                text = raw.decode("utf-8", errors="replace")
            added = self._parse_and_add(text)
            self._sources.append(url)
            logger.info("Loaded %d domains from %s", added, url)
            return added
        except Exception as e:
            logger.error("Failed to fetch blocklist %s: %s", url, e)
            return 0

    def load_from_lines(self, lines: list[str]) -> int:
        """Load domains directly from a list of strings (useful for testing)."""
        added = self._parse_and_add("\n".join(lines))
        return added

    def _parse_and_add(self, text: str) -> int:
        """Parse raw text and add valid domains to the blocked set."""
        added = 0
        for raw_line in text.splitlines():
            line = raw_line.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            # Hosts-format: ``0.0.0.0 example.com`` or ``127.0.0.1 example.com``
            if " " in line or "\t" in line:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                    domain = parts[1].lower().rstrip(".")
                    if domain not in ("localhost", "local", "broadcasthost") and _is_valid_domain(
                        domain
                    ):
                        self._blocked.add(domain)
                        added += 1
                continue

            # Plain domain list
            domain = line.lower().rstrip(".")
            if _is_valid_domain(domain):
                self._blocked.add(domain)
                added += 1

        return added

    # ─── Allowlist ───────────────────────────────────────────────────

    def add_allowlist_entry(self, domain: str) -> None:
        """Add a domain to the allowlist (overrides the blocklist)."""
        self._allowed.add(domain.lower().rstrip("."))

    def remove_allowlist_entry(self, domain: str) -> bool:
        """Remove a domain from the allowlist. Returns True if it was present."""
        key = domain.lower().rstrip(".")
        if key in self._allowed:
            self._allowed.discard(key)
            return True
        return False

    def load_allowlist_from_lines(self, lines: list[str]) -> int:
        """Load allowlist entries from a list of strings."""
        added = 0
        for line in lines:
            domain = line.strip().lower().rstrip(".")
            if domain and _is_valid_domain(domain):
                self._allowed.add(domain)
                added += 1
        return added

    # ─── Query ───────────────────────────────────────────────────────

    def is_blocked(self, domain: str) -> bool:
        """
        Return True if *domain* (or any parent) is on the blocklist and not
        on the allowlist.

        Subdomain matching: if ``ads.example.com`` is queried and
        ``example.com`` is blocked, the query is blocked.
        """
        name = domain.lower().rstrip(".")

        # Allowlist always wins
        if name in self._allowed:
            return False
        # Check the exact name and each parent domain
        parts = name.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._allowed:
                return False

        # Check blocked set — exact match first, then parent wildcards
        if name in self._blocked:
            return True
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._blocked:
                return True

        return False

    # ─── Stats ───────────────────────────────────────────────────────

    @property
    def blocked_count(self) -> int:
        """Total number of blocked domains."""
        return len(self._blocked)

    @property
    def allowed_count(self) -> int:
        """Total number of explicitly allowed domains."""
        return len(self._allowed)

    @property
    def sources(self) -> list[str]:
        """List of loaded sources (paths or URLs)."""
        return list(self._sources)

    def clear(self) -> None:
        """Remove all entries from both lists."""
        self._blocked.clear()
        self._allowed.clear()
        self._sources.clear()
