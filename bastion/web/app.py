"""
Bastion Web Application

Flask application factory that serves the dashboard and REST API.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from flask import Flask, render_template

from bastion.api.routes import api_bp, init_api
from bastion.core.manager import RuleManager
from bastion.core.monitor import NetworkMonitor
from bastion.plugins import PluginManager


def create_app(
    rule_manager: RuleManager,
    monitor: NetworkMonitor,
    plugin_manager: PluginManager,
    demo_mode: bool = False,
) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
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

    # Initialize API with components
    init_api(rule_manager, monitor, plugin_manager)

    # Register blueprints
    app.register_blueprint(api_bp)

    # ─── Dashboard Routes ────────────────────────────────────────

    @app.route("/")
    def dashboard() -> str:
        return render_template("dashboard.html", demo_mode=demo_mode)

    @app.route("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": "0.1.0"}

    return app
