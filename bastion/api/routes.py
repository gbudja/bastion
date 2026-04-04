"""
Bastion REST API

Flask-based REST API providing endpoints for firewall rule management,
system monitoring, and plugin control.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, Response, jsonify, request

from bastion.core.manager import RuleManager
from bastion.core.models import Direction, RuleState
from bastion.core.monitor import NetworkMonitor
from bastion.plugins import PluginManager

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


# ─── Globals set during app initialization ───────────────────────────
_rule_manager: RuleManager | None = None
_monitor: NetworkMonitor | None = None
_plugin_manager: PluginManager | None = None


def init_api(
    rule_manager: RuleManager,
    monitor: NetworkMonitor,
    plugin_manager: PluginManager,
) -> None:
    """Initialize API with application components."""
    global _rule_manager, _monitor, _plugin_manager
    _rule_manager = rule_manager
    _monitor = monitor
    _plugin_manager = plugin_manager


def api_response(
    data: Any = None,
    status: int = 200,
    error: str | None = None,
) -> tuple[Response, int]:
    """Standardized API response format."""
    body: dict[str, Any] = {"success": error is None}
    if data is not None:
        body["data"] = data
    if error:
        body["error"] = error
    return jsonify(body), status


def _parse_enum(value: str | None, enum_type: type[Direction] | type[RuleState]) -> Any:
    """Parse a string into a supported enum value."""
    if value is None:
        return None
    try:
        return enum_type(value)
    except ValueError as exc:
        valid = ", ".join(member.value for member in enum_type)
        raise ValueError(f"Invalid value '{value}'. Expected one of: {valid}") from exc


# ═══════════════════════════════════════════════════════════════════════
#  FIREWALL RULES
# ═══════════════════════════════════════════════════════════════════════


@api_bp.route("/rules", methods=["GET"])
def list_rules() -> tuple[Response, int]:
    """List all firewall rules with optional filtering."""
    assert _rule_manager is not None

    # Query parameters for filtering
    group = request.args.get("group")
    state = request.args.get("state")
    direction = request.args.get("direction")
    query = request.args.get("q")
    tags = request.args.getlist("tag")

    try:
        rules = _rule_manager.search_rules(
            query=query,
            group=group,
            state=_parse_enum(state, RuleState),
            direction=_parse_enum(direction, Direction),
            tags=tags if tags else None,
        )
    except ValueError as exc:
        return api_response(error=str(exc), status=400)

    return api_response([r.to_dict() for r in rules])


@api_bp.route("/rules", methods=["POST"])
def create_rule() -> tuple[Response, int]:
    """Create a new firewall rule."""
    assert _rule_manager is not None

    data = request.get_json(silent=True)
    if not data:
        return api_response(error="Request body must be JSON", status=400)

    try:
        rule = _rule_manager.create_rule(data)
        return api_response(rule.to_dict(), status=201)
    except ValueError as e:
        return api_response(error=str(e), status=400)


@api_bp.route("/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id: str) -> tuple[Response, int]:
    """Get a single rule by ID."""
    assert _rule_manager is not None

    rule = _rule_manager.get_rule(rule_id)
    if not rule:
        return api_response(error="Rule not found", status=404)
    return api_response(rule.to_dict())


@api_bp.route("/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id: str) -> tuple[Response, int]:
    """Update an existing rule."""
    assert _rule_manager is not None

    data = request.get_json(silent=True)
    if not data:
        return api_response(error="Request body must be JSON", status=400)

    try:
        rule = _rule_manager.update_rule(rule_id, data)
        if not rule:
            return api_response(error="Rule not found", status=404)
        return api_response(rule.to_dict())
    except ValueError as e:
        return api_response(error=str(e), status=400)


@api_bp.route("/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id: str) -> tuple[Response, int]:
    """Delete a rule."""
    assert _rule_manager is not None

    if _rule_manager.delete_rule(rule_id):
        return api_response({"deleted": rule_id})
    return api_response(error="Rule not found", status=404)


@api_bp.route("/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id: str) -> tuple[Response, int]:
    """Toggle a rule between enabled and disabled."""
    assert _rule_manager is not None

    rule = _rule_manager.toggle_rule(rule_id)
    if not rule:
        return api_response(error="Rule not found", status=404)
    return api_response(rule.to_dict())


@api_bp.route("/rules/groups", methods=["GET"])
def list_rule_groups() -> tuple[Response, int]:
    """List all rule groups with their rules."""
    assert _rule_manager is not None

    groups = _rule_manager.get_groups()
    result = {name: [r.to_dict() for r in rules] for name, rules in groups.items()}
    return api_response(result)


# ─── Apply & Validate ────────────────────────────────────────────────


@api_bp.route("/rules/apply", methods=["POST"])
def apply_rules() -> tuple[Response, int]:
    """Apply the current ruleset to the system."""
    assert _rule_manager is not None
    result = _rule_manager.apply()
    status = 200 if result.get("success") else 500
    return api_response(result, status=status)


@api_bp.route("/rules/validate", methods=["GET"])
def validate_rules() -> tuple[Response, int]:
    """Validate the current ruleset (dry run)."""
    assert _rule_manager is not None
    result = _rule_manager.validate()
    return api_response(result)


@api_bp.route("/rules/rollback", methods=["POST"])
def rollback_rules() -> tuple[Response, int]:
    """Rollback to the previous ruleset."""
    assert _rule_manager is not None
    success = _rule_manager.rollback()
    if success:
        return api_response({"rolled_back": True})
    return api_response(error="No previous state available for rollback", status=400)


# ═══════════════════════════════════════════════════════════════════════
#  MONITORING
# ═══════════════════════════════════════════════════════════════════════


@api_bp.route("/monitor/stats", methods=["GET"])
def get_stats() -> tuple[Response, int]:
    """Get current system and network statistics."""
    assert _monitor is not None
    return api_response(_monitor.get_dashboard_data())


@api_bp.route("/monitor/hosts", methods=["GET"])
def get_hosts() -> tuple[Response, int]:
    """Get discovered network hosts."""
    assert _monitor is not None
    hosts = _monitor.discover_hosts()
    return api_response(
        [
            {
                "ip": h.ip_address,
                "mac": h.mac_address,
                "hostname": h.hostname,
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
                "connections": h.active_connections,
            }
            for h in hosts
        ]
    )


@api_bp.route("/monitor/sessions", methods=["GET"])
def get_sessions() -> tuple[Response, int]:
    """Get active network sessions."""
    import psutil

    connections = psutil.net_connections(kind="inet")
    sessions = []
    for conn in connections:
        if conn.status == "ESTABLISHED" and conn.raddr:
            sessions.append(
                {
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "pid": conn.pid,
                }
            )
    return api_response(sessions[:200])  # Limit to 200 sessions


# ═══════════════════════════════════════════════════════════════════════
#  PLUGINS
# ═══════════════════════════════════════════════════════════════════════


@api_bp.route("/plugins", methods=["GET"])
def list_plugins() -> tuple[Response, int]:
    """List all plugins and their status."""
    assert _plugin_manager is not None
    return api_response(_plugin_manager.get_status())


@api_bp.route("/plugins/<name>/enable", methods=["POST"])
def enable_plugin(name: str) -> tuple[Response, int]:
    """Enable a plugin."""
    assert _plugin_manager is not None
    config = request.get_json(silent=True) or {}
    if _plugin_manager.enable_plugin(name, config):
        return api_response({"enabled": name})
    return api_response(error=f"Failed to enable plugin '{name}'", status=400)


@api_bp.route("/plugins/<name>/disable", methods=["POST"])
def disable_plugin(name: str) -> tuple[Response, int]:
    """Disable a plugin."""
    assert _plugin_manager is not None
    if _plugin_manager.disable_plugin(name):
        return api_response({"disabled": name})
    return api_response(error=f"Failed to disable plugin '{name}'", status=400)


@api_bp.route("/plugins/<name>/routes", methods=["GET"])
def list_plugin_routes(name: str) -> tuple[Response, int]:
    """List API routes exposed by a plugin."""
    assert _plugin_manager is not None
    plugin = _plugin_manager.get_plugin(name)
    if plugin is None:
        return api_response(error=f"Plugin '{name}' not found", status=404)

    routes = [
        {
            "method": route["method"],
            "path": route["path"],
            "description": route.get("description", ""),
        }
        for route in plugin.get_api_routes()
    ]
    return api_response(routes)


@api_bp.route("/plugins/<name>/api/<path:subpath>", methods=["GET", "POST"])
def call_plugin_route(name: str, subpath: str) -> tuple[Response, int]:
    """Invoke a plugin-defined API route through a stable proxy endpoint."""
    assert _plugin_manager is not None
    plugin = _plugin_manager.get_plugin(name)
    if plugin is None:
        return api_response(error=f"Plugin '{name}' not found", status=404)

    for route in plugin.get_api_routes():
        if route["method"] == request.method and route["path"].strip("/") == subpath.strip("/"):
            handler = route["handler"]
            try:
                payload = request.get_json(silent=True) if request.method == "POST" else None
                return api_response(handler(payload))
            except ValueError as exc:
                return api_response(error=str(exc), status=400)
            except Exception as exc:  # pragma: no cover
                logger.exception("Plugin API route failed: %s", exc)
                return api_response(error="Plugin route failed", status=500)

    return api_response(error=f"Plugin route '{subpath}' not found", status=404)


# ═══════════════════════════════════════════════════════════════════════
#  SYSTEM
# ═══════════════════════════════════════════════════════════════════════


@api_bp.route("/system/info", methods=["GET"])
def system_info() -> tuple[Response, int]:
    """Get Bastion system information."""
    import platform

    return api_response(
        {
            "version": "0.1.0",
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "nftables_available": _rule_manager.backend.is_available() if _rule_manager else False,
        }
    )
