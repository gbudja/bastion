"""
Bastion Web Application

Flask application factory that serves the dashboard and REST API.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, render_template, send_from_directory

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

    app.config["SECRET_KEY"] = os.environ.get("BASTION_SECRET_KEY", os.urandom(32).hex())
    app.config["DEMO_MODE"] = demo_mode

    # Initialize API with components
    init_api(rule_manager, monitor, plugin_manager)

    # Register blueprints
    app.register_blueprint(api_bp)

    # ─── Dashboard Routes ────────────────────────────────────────

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", demo_mode=demo_mode)

    @app.route("/rules")
    def rules_page():
        return render_template("rules.html", demo_mode=demo_mode)

    @app.route("/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    return app
