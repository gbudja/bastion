"""
Bastion Web Application

Flask application factory that serves the dashboard and REST API.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request

from bastion import __version__
from bastion.api.routes import api_bp, init_api
from bastion.core.manager import RuleManager
from bastion.core.monitor import NetworkMonitor
from bastion.plugins import PluginManager

# Mutating HTTP methods that require CSRF protection.
_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def create_app(
    rule_manager: RuleManager,
    monitor: NetworkMonitor,
    plugin_manager: PluginManager,
    demo_mode: bool = False,
) -> Flask:
    """Create and configure the Flask application."""
    static_dir = Path(__file__).parent / "static"
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(static_dir) if static_dir.exists() else None,
    )

    # Secret key must come from environment — never hardcoded in production.
    # Fall back to a random key for demo/dev runs only.
    secret_key = os.environ.get("BASTION_SECRET_KEY")
    if not secret_key and not demo_mode:
        raise RuntimeError("BASTION_SECRET_KEY must be set when demo mode is disabled")
    if not secret_key:
        secret_key = secrets.token_hex(32)

    app.config["SECRET_KEY"] = secret_key
    app.config["DEMO_MODE"] = demo_mode

    # ─── CSRF token (one per process, regenerated on restart) ────
    _csrf_token = secrets.token_hex(32)

    # Initialize API with components
    init_api(rule_manager, monitor, plugin_manager)

    # Register blueprints
    app.register_blueprint(api_bp)

    # ─── CSRF + Origin enforcement for mutating API requests ─────
    @app.before_request
    def enforce_csrf_and_origin() -> None:
        """Block mutating /api/ requests that lack a valid CSRF token."""
        if request.method not in _MUTATING_METHODS:
            return
        if not request.path.startswith("/api/"):
            return

        # Check CSRF token header
        token = request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, _csrf_token):
            abort(403, description="Missing or invalid CSRF token")

        # Origin check — if the browser sent an Origin header, it must
        # match the Host header to prevent cross-site requests.
        origin = request.headers.get("Origin")
        if origin:
            from urllib.parse import urlparse

            origin_host = urlparse(origin).netloc
            expected_host = request.host  # includes port
            if origin_host != expected_host:
                abort(403, description="Origin mismatch")

    # ─── Security response headers ──────────────────────────────
    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ─── Dashboard Routes ────────────────────────────────────────

    @app.route("/")
    def dashboard() -> str:
        return render_template("dashboard.html", demo_mode=demo_mode, csrf_token=_csrf_token)

    @app.route("/health")
    def health() -> tuple[Response, int]:
        return jsonify({"status": "ok", "version": __version__}), 200

    return app
